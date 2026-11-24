"""Automatic uploader.

Reads the suite manifest (``index.json``) and uploads every payload to the
target endpoint, recording the server's response per payload back into the
manifest and into a results report.

The endpoint is described by a raw ``request.txt`` copied verbatim from an
intercepting proxy (Burp Suite, Caido, ZAP, mitmproxy). The method, URL,
headers, authentication cookies/tokens, multipart boundary and file field are
all extracted from that file; the uploader swaps only the file's bytes and
filename for each payload, so every request carries the exact session the
operator captured.

Authorized testing only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

from .. import rawhttp
from ..manifest import Manifest, ManifestEntry


# --------------------------------------------------------------------------- #
# Building the template request
# --------------------------------------------------------------------------- #
def build_template(args) -> rawhttp.UploadTemplate:
    """Build the upload template from --request-file, or from --url."""
    url = getattr(args, "url", None)
    scheme = getattr(args, "scheme", None)
    field = getattr(args, "field", None)
    raw_body = getattr(args, "raw_body", False)
    if args.request_file:
        req = rawhttp.load_request_file(args.request_file, scheme=scheme)
        if url:                              # allow overriding the captured URL
            _apply_url_override(req, url)
        return rawhttp.UploadTemplate.from_request(
            req, field=field, raw_body=raw_body)

    # No request.txt: synthesise a minimal multipart POST from --url.
    if not url:
        raise SystemExit("error: pass --request-file request.txt (from Burp/Caido) "
                         "or --url to build the request.")
    boundary = "----uploadArsenal" + os.urandom(8).hex()
    field = args.field or "file"
    req = rawhttp.RawRequest(
        method="POST", target="/", version="HTTP/1.1",
        headers=[("Content-Type", f"multipart/form-data; boundary={boundary}"),
                 ("User-Agent", "upload-arsenal")],
        body=rawhttp.build_multipart(
            [rawhttp.Part(
                headers=[("Content-Disposition",
                          f'form-data; name="{field}"; filename="placeholder"'),
                         ("Content-Type", "application/octet-stream")],
                data=b"")],
            boundary),
    )
    _apply_url_override(req, url)
    return rawhttp.UploadTemplate.from_request(req, field=field)


def _apply_url_override(req: rawhttp.RawRequest, url: str) -> None:
    from urllib.parse import urlsplit
    u = urlsplit(url if "://" in url else "https://" + url)
    req.scheme = u.scheme.lower()
    req.host, req.port = rawhttp._split_hostport(
        u.netloc, req.scheme)  # noqa: SLF001 (internal helper reuse)
    req.target = (u.path or "/") + (f"?{u.query}" if u.query else "")
    req.set_header("Host", req.authority)


# --------------------------------------------------------------------------- #
# Response matching
# --------------------------------------------------------------------------- #
def classify(resp: rawhttp.Response, args) -> tuple[str, str]:
    """Return (verdict, note). verdict in accepted|rejected|error|unknown."""
    if resp.error:
        return "error", resp.error
    text = resp.text(4096)
    if args.fail_regex and re.search(args.fail_regex, text, re.I):
        return "rejected", f"matched --fail-regex"
    if args.success_regex:
        if re.search(args.success_regex, text, re.I):
            return "accepted", "matched --success-regex"
        return "rejected", "no --success-regex match"
    # Heuristic default.
    if resp.status in (200, 201, 204):
        if re.search(r"error|invalid|not allowed|forbidden|denied|rejected|"
                     r"unsupported|fail", text, re.I):
            return "unknown", f"{resp.status} but body mentions an error"
        return "accepted", f"HTTP {resp.status}"
    if resp.status in (400, 403, 415, 422):
        return "rejected", f"HTTP {resp.status}"
    return "unknown", f"HTTP {resp.status}"


_URL_RE = re.compile(r'https?://[^\s"\'<>)\]]+', re.I)
_PATH_RE = re.compile(r'(?:"|\')(/[^"\'\s<>]+?\.[A-Za-z0-9]{1,5})(?:"|\')')


def extract_locations(resp: rawhttp.Response, filename: str) -> list[str]:
    """Pull candidate stored-file URLs/paths out of a response body."""
    text = resp.text(16384)
    found: list[str] = []
    for m in _URL_RE.finditer(text):
        found.append(m.group(0).rstrip(".,"))
    for m in _PATH_RE.finditer(text):
        found.append(m.group(1))
    # anything echoing the (base) filename is a strong hint
    stem = re.sub(r"[^A-Za-z0-9._-]", "", os.path.basename(filename))
    if stem:
        for m in re.finditer(re.escape(stem) + r"[A-Za-z0-9._/-]*", text):
            found.append(m.group(0))
    loc = resp.get_header("Location")
    if loc:
        found.insert(0, loc)
    # dedup, keep order
    seen, out = set(), []
    for f in found:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out[:20]


# --------------------------------------------------------------------------- #
# Filenames
# --------------------------------------------------------------------------- #
def payload_filename(entry: ManifestEntry, template_name: str | None) -> str:
    """Pick the filename sent for a payload.

    Keeps the generated basename (which already encodes the technique, e.g.
    ``poc.php.png``) but borrows the extension from the captured request when
    that request used a specific one and the payload is extension-agnostic.
    """
    base = os.path.basename(entry.path)
    return base


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="upload-arsenal-upload",
        description="Upload each payload from a generated suite to a target and "
                    "record the response. Reads a raw request.txt from Burp/Caido "
                    "for the endpoint, headers and auth. Authorized testing only.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  upload-arsenal-upload -m suite/index.json -r request.txt\n"
               "  upload-arsenal-upload -m suite -r req.txt --risk safe --delay 0.5\n"
               "  upload-arsenal-upload -m suite -r req.txt --proxy http://127.0.0.1:8080\n"
               "  upload-arsenal-upload -m suite -r req.txt \\\n"
               "        --success-regex 'upload (ok|complete)' --fail-regex 'not allowed'\n",
    )
    p.add_argument("-m", "--manifest", required=True,
                   help="path to index.json or the suite directory")
    src = p.add_argument_group("target request")
    src.add_argument("-r", "--request-file",
                     help="raw request copied from Burp/Caido (request.txt)")
    src.add_argument("--url", help="target URL (overrides request.txt, or builds "
                                   "a minimal multipart POST if used alone)")
    src.add_argument("--field", help="multipart field name to replace "
                                     "(needed when the request has several file parts)")
    src.add_argument("--raw-body", action="store_true",
                     help="replace the whole body instead of a multipart part "
                          "(PUT/raw uploads)")
    src.add_argument("--scheme", choices=["http", "https"],
                     help="force the scheme when request.txt omits it")

    net = p.add_argument_group("networking")
    net.add_argument("--proxy", help="route through an HTTP proxy, e.g. "
                                     "http://127.0.0.1:8080 (Burp/Caido)")
    net.add_argument("--timeout", type=float, default=20.0)
    net.add_argument("--delay", type=float, default=0.0,
                     help="seconds to sleep between uploads (rate-limit)")
    net.add_argument("--follow-redirects", action="store_true")
    net.add_argument("--verify-tls", action="store_true",
                     help="verify TLS certs (off by default for proxied/lab targets)")

    sel = p.add_argument_group("selection")
    sel.add_argument("--risk", action="append",
                     choices=["safe", "active", "destructive"],
                     help="only upload payloads at these risk levels (repeatable)")
    sel.add_argument("--category", action="append", help="only these categories")
    sel.add_argument("--technique", action="append", help="only these techniques")
    sel.add_argument("--language", action="append", help="only these languages")
    sel.add_argument("--limit", type=int, help="upload at most N payloads")

    out = p.add_argument_group("matching / output")
    out.add_argument("--success-regex", help="body regex meaning 'accepted'")
    out.add_argument("--fail-regex", help="body regex meaning 'rejected'")
    out.add_argument("--content-type", default="guess", metavar="MODE",
                     help="per-part Content-Type: 'guess' (from filename), "
                          "'keep' (the captured value), or a literal MIME type "
                          "like image/png (default: guess)")
    out.add_argument("-o", "--report", help="write a JSON+HTML results report "
                                             "(default: <suite>/upload_results.*)")
    out.add_argument("--no-manifest-update", action="store_true",
                     help="do not write results back into index.json")
    out.add_argument("--dry-run", action="store_true",
                     help="show what would be uploaded without sending")
    out.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    man = Manifest.load(args.manifest)
    try:
        template = build_template(args)
    except rawhttp.RawRequestError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    entries = man.filter(
        risk=set(args.risk) if args.risk else None,
        category=set(args.category) if args.category else None,
        technique=set(args.technique) if args.technique else None,
        language=set(args.language) if args.language else None,
    )
    if args.limit:
        entries = entries[:args.limit]

    if not args.quiet:
        where = "multipart field %r" % template.field if template.is_multipart \
            else "raw request body"
        print(f"[*] target : {template.request.method} {template.request.url}")
        print(f"[*] slot   : {where}")
        for line in rawhttp.describe_auth(template.request):
            print(f"[*] auth   : {line}")
        print(f"[*] payloads: {len(entries)} selected")

    if args.dry_run:
        for e in entries:
            print(f"    {e.risk:11} {e.path}")
        print("[dry-run] nothing sent.")
        return 0

    results = []
    counts = {"accepted": 0, "rejected": 0, "error": 0, "unknown": 0}
    for i, entry in enumerate(entries, 1):
        try:
            data = man.read_bytes(entry)
        except OSError as e:
            if not args.quiet:
                print(f"[!] {entry.path}: cannot read ({e})")
            continue
        filename = payload_filename(entry, template.original_filename)
        req = template.render(data, filename, content_type=args.content_type)
        resp = rawhttp.send(req, timeout=args.timeout, proxy=args.proxy,
                            verify=args.verify_tls,
                            follow_redirects=args.follow_redirects)
        verdict, note = classify(resp, args)
        counts[verdict] += 1
        locations = extract_locations(resp, filename) if not resp.error else []
        result = {
            "status": resp.status, "verdict": verdict, "note": note,
            "bytes": len(resp.body), "elapsed": round(resp.elapsed, 3),
            "filename": filename, "locations": locations,
        }
        if resp.error:
            result["error"] = resp.error
        results.append({"path": entry.path, "risk": entry.risk,
                        "technique": entry.technique, **result})
        if not args.no_manifest_update:
            entry.result = result
            if locations:
                for l in locations:
                    if l not in entry.found_at:
                        entry.found_at.append(l)
        if not args.quiet:
            tag = {"accepted": "+", "rejected": "-",
                   "error": "x", "unknown": "?"}[verdict]
            print(f"[{tag}] {i:>3}/{len(entries)} {entry.path:50} "
                  f"{resp.status or '---'} {verdict} ({note})")
        if args.delay:
            time.sleep(args.delay)

    report_base = args.report or os.path.join(man.root, "upload_results")
    _write_report(results, counts, template, report_base)
    if not args.no_manifest_update:
        man.save()

    if not args.quiet:
        print(f"\n[=] accepted={counts['accepted']} rejected={counts['rejected']} "
              f"unknown={counts['unknown']} error={counts['error']}")
        print(f"[+] report : {report_base}.json / {report_base}.html")
        if not args.no_manifest_update:
            print(f"[+] manifest updated with per-payload results")
    return 0


def _write_report(results, counts, template, base) -> None:
    import html
    with open(base + ".json", "w") as f:
        json.dump({"target": template.request.url,
                   "method": template.request.method,
                   "counts": counts, "results": results}, f, indent=2)
    rows = "\n".join(
        "<tr class='{v}'>"
        f"<td><code>{html.escape(r['path'])}</code></td>"
        f"<td>{r['risk']}</td>"
        f"<td>{r.get('status','')}</td>"
        f"<td>{html.escape(r['verdict'])}</td>"
        f"<td>{html.escape(str(r.get('note','')))}</td>"
        f"<td>{'<br>'.join(html.escape(x) for x in r.get('locations', [])[:5])}</td>"
        "</tr>".format(v=r['verdict'])
        for r in results
    )
    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Upload Arsenal — upload results</title><style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#222}}
 table{{border-collapse:collapse;width:100%}}
 th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}}
 th{{background:#f5f5f5}} code{{background:#f0f0f0;padding:0 .2rem}}
 tr.accepted{{background:#e8f5e9}} tr.rejected{{background:#ffebee}}
 tr.error{{background:#fff3e0}} tr.unknown{{background:#f3e5f5}}
</style></head><body>
<h1>Upload results</h1>
<p>{html.escape(template.request.method)} {html.escape(template.request.url)}<br>
accepted={counts['accepted']} · rejected={counts['rejected']} ·
unknown={counts['unknown']} · error={counts['error']}</p>
<table><thead><tr><th>Payload</th><th>Risk</th><th>HTTP</th><th>Verdict</th>
<th>Note</th><th>Stored at (candidates)</th></tr></thead><tbody>
{rows}
</tbody></table></body></html>"""
    with open(base + ".html", "w") as f:
        f.write(doc)


if __name__ == "__main__":
    raise SystemExit(main())
