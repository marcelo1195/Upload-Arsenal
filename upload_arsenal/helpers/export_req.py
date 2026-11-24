"""Raw-request exporter.

Turns each generated payload into a ready-to-send raw HTTP request (``.req``)
built on a captured ``request.txt`` template, so the operator can:

* drop a ``.req`` straight into **Burp Repeater** ("Paste from file"), or
* fuzz with **ffuf**/**wfuzz** using ``-request <file>``, or
* replay with ``curl`` via the generated helper.

Each ``.req`` carries the real session (cookies, auth headers, boundary) with
only the file part swapped for that payload. An ``ffuf`` marker variant is also
emitted, where the file bytes are replaced by ``FUZZ`` so one request template
can iterate the whole payload directory.

Authorized testing only.
"""
from __future__ import annotations

import argparse
import os
import sys

from .. import rawhttp
from ..manifest import Manifest
from .uploader import build_template, payload_filename


def _safe_name(path: str) -> str:
    return path.replace("/", "__").replace("\\", "__")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="upload-arsenal-export",
        description="Export each payload as a raw .req request (Burp Repeater / "
                    "ffuf -request) built on a captured request.txt. "
                    "Authorized use only.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  upload-arsenal-export -m suite -r request.txt -o reqs/\n"
               "  upload-arsenal-export -m suite -r request.txt --risk safe\n"
               "  upload-arsenal-export -m suite -r request.txt --ffuf-template\n"
               "\nffuf:  ffuf -request reqs/<file>.req -request-proto https \\\n"
               "            -w payloads.txt   # with --ffuf-template\n",
    )
    p.add_argument("-m", "--manifest", required=True, help="index.json or suite dir")
    p.add_argument("-r", "--request-file", required=True,
                   help="raw request template copied from Burp/Caido")
    p.add_argument("--field", help="multipart field to replace (if ambiguous)")
    p.add_argument("--raw-body", action="store_true",
                   help="replace the whole body (raw/PUT uploads)")
    p.add_argument("--scheme", choices=["http", "https"])
    p.add_argument("-o", "--outdir", default=None,
                   help="output directory for .req files (default: <suite>/requests)")
    p.add_argument("--content-type", default="guess", metavar="MODE",
                   help="per-part Content-Type: guess | keep | a literal MIME")

    sel = p.add_argument_group("selection")
    sel.add_argument("--risk", action="append",
                     choices=["safe", "active", "destructive"])
    sel.add_argument("--category", action="append")
    sel.add_argument("--technique", action="append")
    sel.add_argument("--language", action="append")
    sel.add_argument("--limit", type=int)

    extra = p.add_argument_group("extras")
    extra.add_argument("--ffuf-template", action="store_true",
                       help="also emit upload_FUZZ.req with the file bytes set to "
                            "FUZZ, plus a payload wordlist for ffuf -w")
    extra.add_argument("--curl", action="store_true",
                       help="also emit a replay.sh of curl commands")
    extra.add_argument("--version-line", default="HTTP/1.1",
                       help="request-line HTTP version to write (default: HTTP/1.1; "
                            "HTTP/2 captures are downgraded for Repeater)")
    extra.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    man = Manifest.load(args.manifest)
    try:
        template = build_template(args)
    except rawhttp.RawRequestError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    outdir = args.outdir or os.path.join(man.root, "requests")
    os.makedirs(outdir, exist_ok=True)

    entries = man.filter(
        risk=set(args.risk) if args.risk else None,
        category=set(args.category) if args.category else None,
        technique=set(args.technique) if args.technique else None,
        language=set(args.language) if args.language else None,
    )
    if args.limit:
        entries = entries[:args.limit]

    curl_lines = ["#!/bin/sh",
                  "# Replay generated upload requests with curl. Authorized use only.",
                  "set -e"]
    written = 0
    index_rows = []
    for entry in entries:
        try:
            data = man.read_bytes(entry)
        except OSError:
            continue
        filename = payload_filename(entry)
        req = template.render(data, filename, content_type=args.content_type)
        raw = req.to_bytes(version=args.version_line)
        name = _safe_name(entry.path) + ".req"
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(raw)
        written += 1
        index_rows.append((name, entry.path, entry.risk))
        if args.curl:
            curl_lines.append(_curl_for(req, data, filename, template))

    # ffuf template: body with FUZZ as the file content + a payload wordlist.
    if args.ffuf_template:
        _write_ffuf_template(template, outdir, entries, man, args)

    if args.curl:
        sh = os.path.join(outdir, "replay.sh")
        with open(sh, "w") as f:
            f.write("\n".join(curl_lines) + "\n")
        os.chmod(sh, 0o755)

    # a small index so the operator knows which .req is which
    with open(os.path.join(outdir, "INDEX.txt"), "w") as f:
        f.write("# .req file  <-  payload  (risk)\n")
        for name, path, risk in index_rows:
            f.write(f"{name}\t{path}\t{risk}\n")

    if not args.quiet:
        print(f"[+] wrote {written} .req file(s) to {outdir}/")
        print(f"[*] Burp: Repeater > paste from file. "
              f"ffuf: ffuf -request <file>.req"
              + ("  (use upload_FUZZ.req + payloads.txt)" if args.ffuf_template else ""))
        if args.curl:
            print(f"[*] curl replay: {os.path.join(outdir, 'replay.sh')}")
    return 0


def _curl_for(req: rawhttp.RawRequest, data: bytes, filename: str,
              template) -> str:
    """A curl command replaying one request (multipart via -F when possible)."""
    import shlex
    parts = ["curl", "-sk", "-X", req.method]
    for k, v in req.headers:
        if k.lower() in ("content-length", "content-type") and template.is_multipart:
            continue  # let curl set the multipart Content-Type/length
        if k.lower() == "host":
            continue
        parts += ["-H", shlex.quote(f"{k}: {v}")]
    if template.is_multipart:
        # reference the sibling payload file rather than inlining bytes
        parts += ["-F", shlex.quote(
            f"{template.field}=@PAYLOAD_DIR/{os.path.basename(filename)}"
            f";filename={filename}")]
    else:
        parts += ["--data-binary", "@PAYLOAD_DIR/" + os.path.basename(filename)]
    parts.append(shlex.quote(req.url))
    return "# " + os.path.basename(filename) + "\n" + " ".join(parts)


def _write_ffuf_template(template, outdir, entries, man, args) -> None:
    """Emit upload_FUZZ.req (file bytes = FUZZ) and a payloads.txt wordlist.

    ffuf reads the request, replaces FUZZ with each wordlist line, and fixes
    Content-Length automatically. We list payload *file paths* so the operator
    pairs it with `-w payloads.txt` and ffuf's `FUZZ` in a file reference, or
    inlines small payloads. For binary payloads, prefer the per-payload .req
    files instead.
    """
    marker = b"FUZZ"
    req = template.render(marker, "FUZZ", content_type=args.content_type)
    raw = req.to_bytes(version=args.version_line)
    with open(os.path.join(outdir, "upload_FUZZ.req"), "wb") as f:
        f.write(raw)
    # a wordlist of payload file paths (operator points ffuf at these)
    with open(os.path.join(outdir, "payloads.txt"), "w") as f:
        for e in entries:
            f.write(man.artifact_path(e) + "\n")
    with open(os.path.join(outdir, "FFUF_README.txt"), "w") as f:
        f.write(
            "ffuf raw-request mode\n"
            "=====================\n"
            "Per-payload (recommended, handles binary): send each .req file:\n"
            "  for r in *.req; do ffuf -request \"$r\" -request-proto "
            f"{template.request.scheme}; done\n\n"
            "Single template with FUZZ in the file content (text payloads only):\n"
            f"  ffuf -request upload_FUZZ.req -request-proto {template.request.scheme} "
            "-w payloads.txt\n"
            "Note: upload_FUZZ.req puts the literal string FUZZ where the file "
            "bytes go; ffuf substitutes each wordlist line and recomputes "
            "Content-Length. Binary payloads (polyglots, zip, images) won't "
            "survive line-based substitution — use the per-payload .req files "
            "for those.\n")


if __name__ == "__main__":
    raise SystemExit(main())
