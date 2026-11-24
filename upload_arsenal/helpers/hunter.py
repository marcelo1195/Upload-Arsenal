"""Stored-file hunter.

After a file is accepted by an upload endpoint, the next question is *where did
it land* and *under what name*. This tool probes common storage layouts and
server-side renaming schemes to locate the stored artifact, confirming it by
matching a marker the payload contains (so a 200 on a catch-all page is not
mistaken for a hit).

It reuses the captured ``request.txt`` only for its scheme/host/auth; the
probes are GET requests to candidate URLs.

Authorized testing only.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import os
import re
import sys
import time

from .. import rawhttp
from ..manifest import Manifest, ManifestEntry


# --------------------------------------------------------------------------- #
# Candidate path generation
# --------------------------------------------------------------------------- #
DEFAULT_DIRS = [
    "", "uploads/", "upload/", "files/", "file/", "media/", "images/", "img/",
    "assets/", "static/", "public/", "data/", "tmp/", "temp/", "attachments/",
    "documents/", "docs/", "content/", "userfiles/", "user_uploads/",
    "storage/", "storage/uploads/", "public/uploads/", "wp-content/uploads/",
    "sites/default/files/", "fileadmin/", "cdn/", "s3/",
]

# Server-side renaming schemes. Each returns a list of candidate basenames
# given the original (basename, stem, ext).
def _rename_schemes(basename: str, stem: str, ext: str, *, now) -> list[str]:
    ts = str(int(now))
    ymd = _dt.datetime.fromtimestamp(now, _dt.timezone.utc).strftime("%Y%m%d")
    md5 = hashlib.md5(basename.encode()).hexdigest()
    sha1 = hashlib.sha1(basename.encode()).hexdigest()
    out = [
        basename,                       # kept as-is
        stem.lower() + ext,             # lowercased
        re.sub(r"[^A-Za-z0-9.]+", "_", basename),   # sanitised
        re.sub(r"[^A-Za-z0-9.]+", "-", basename),
        f"{stem}_{ts}{ext}",            # name + unix ts
        f"{ts}_{basename}",
        f"{ts}{ext}",                   # pure timestamp
        f"{ymd}_{basename}",
        f"{ymd}/{basename}",            # date-sharded dir
        md5 + ext, sha1 + ext,          # hash of name
        md5[:16] + ext,
    ]
    return out


def candidate_urls(base_url: str, filename: str, dirs, *, date_dirs=True) -> list[str]:
    """Candidate URLs, ordered most-likely-first.

    Ordering matters because callers cap the number of probes: it is
    name-major, so the *unchanged* filename is tried in **every** directory
    before any rename scheme is attempted. Directory-major ordering would
    spend the whole budget on the first few directories and never probe
    common ones like ``wp-content/uploads/`` at all.
    """
    # strip filter-bypass junk so the "stored" name is realistic
    clean = re.sub(r"(%00|%20|%0a|%0d|::\$DATA)", "", filename)
    now = time.time()
    names = _rename_schemes(clean, os.path.splitext(clean)[0],
                            os.path.splitext(clean)[1], now=now)
    utc = _dt.datetime.fromtimestamp(now, _dt.timezone.utc)
    shards = [""]
    if date_dirs:
        shards += [utc.strftime("%Y/%m/%d/"), utc.strftime("%Y-%m/")]
    base = base_url.rstrip("/") + "/"
    urls, seen = [], set()
    for name in names:
        for shard in shards:
            for d in dirs:
                url = base + d + shard + name
                if url not in seen:
                    seen.add(url)
                    urls.append(url)
    return urls


# --------------------------------------------------------------------------- #
# Confirmation marker
# --------------------------------------------------------------------------- #
def payload_marker(data: bytes) -> bytes | None:
    """A distinctive byte-string the stored file should contain if it's ours."""
    for needle in (b"upload-arsenal", b"ua-exif", b"ua-msl-out",
                   b"code execution confirmed"):
        if needle in data:
            return needle
    # fall back to a stable hash prefix of the payload body
    return None


def confirm(resp: rawhttp.Response, marker: bytes | None, data: bytes) -> bool:
    if resp.status != 200 or resp.error:
        return False
    if marker:
        return marker in resp.body
    # No textual marker: compare a content fingerprint (first/last bytes + len).
    if len(resp.body) == len(data) and resp.body[:32] == data[:32]:
        return True
    return False


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="upload-arsenal-hunt",
        description="Locate where uploaded files were stored by probing common "
                    "path layouts and rename schemes, confirmed by a payload "
                    "marker. Authorized use only.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  upload-arsenal-hunt -m suite --base-url https://t/ \\\n"
               "       --filename poc.php.png\n"
               "  upload-arsenal-hunt -m suite -r request.txt   # hunt accepted uploads\n"
               "  upload-arsenal-hunt -m suite --base-url https://t/uploads/ \\\n"
               "       --extra-dir incoming/ --proxy http://127.0.0.1:8080\n",
    )
    p.add_argument("-m", "--manifest", help="index.json or suite dir")
    p.add_argument("--base-url", help="base URL where stored files may be served, "
                                      "e.g. https://target/ or https://cdn/uploads/")
    p.add_argument("-r", "--request-file",
                   help="request.txt (Burp/Caido) to borrow scheme/host/auth from; "
                        "--base-url defaults to its origin")
    p.add_argument("--filename", action="append", default=[],
                   help="hunt a specific stored filename (repeatable). Default: "
                        "every payload the manifest marked 'accepted'.")
    p.add_argument("--all", action="store_true",
                   help="hunt every payload in the manifest, not just accepted ones")
    p.add_argument("--extra-dir", action="append", default=[],
                   help="additional directory prefix to probe (repeatable)")
    p.add_argument("--no-date-dirs", action="store_true",
                   help="skip date-sharded directory guesses")
    p.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("--verify-tls", action="store_true")
    p.add_argument("--max-per-file", type=int, default=400,
                   help="cap candidate URLs probed per file (default: 400)")
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def _resolve_base_url(args) -> tuple[str, rawhttp.RawRequest | None]:
    tmpl = None
    if args.request_file:
        tmpl = rawhttp.load_request_file(args.request_file)
    if args.base_url:
        return args.base_url, tmpl
    if tmpl:
        return f"{tmpl.scheme}://{tmpl.authority}/", tmpl
    raise SystemExit("error: pass --base-url or --request-file to locate the host.")


def _auth_headers(tmpl: rawhttp.RawRequest | None) -> list:
    """Carry cookies / auth headers from the captured request into probes."""
    if not tmpl:
        return [("User-Agent", "upload-arsenal")]
    keep = []
    for k, v in tmpl.headers:
        if k.lower() in ("cookie", "authorization", "user-agent") or (
                k.lower().startswith("x-") and
                re.search(r"token|csrf|xsrf|api|auth", k, re.I)):
            keep.append((k, v))
    if not any(k.lower() == "user-agent" for k, _ in keep):
        keep.append(("User-Agent", "upload-arsenal"))
    return keep


def _probe(url: str, headers, args) -> rawhttp.Response:
    from urllib.parse import urlsplit
    u = urlsplit(url)
    scheme = u.scheme or "https"
    host, port = rawhttp.split_hostport(u.netloc, scheme)
    req = rawhttp.RawRequest(
        method="GET",
        target=(u.path or "/") + (f"?{u.query}" if u.query else ""),
        scheme=scheme, host=host, port=port,
    )
    req.headers = [("Host", req.authority)] + list(headers)
    return rawhttp.send(req, timeout=args.timeout, proxy=args.proxy,
                        verify=args.verify_tls, follow_redirects=True)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    man = Manifest.load(args.manifest) if args.manifest else None
    base_url, tmpl = _resolve_base_url(args)
    headers = _auth_headers(tmpl)
    dirs = DEFAULT_DIRS + list(args.extra_dir)

    # Build the hunt list: (filename, data_bytes, entry_or_None).
    targets = []
    if args.filename:
        for name in args.filename:
            data = b""
            entry = None
            if man:
                entry = next((e for e in man.entries
                              if os.path.basename(e.path) == name), None)
                if entry:
                    try:
                        data = man.read_bytes(entry)
                    except OSError:
                        pass
            targets.append((name, data, entry))
    elif man:
        for e in man.entries:
            accepted = (e.result.get("verdict") == "accepted") if e.result else False
            if not args.all and not accepted:
                continue
            try:
                data = man.read_bytes(e)
            except OSError:
                data = b""
            name = (e.result.get("filename") if e.result else None) \
                or os.path.basename(e.path)
            targets.append((name, data, e))
    if not targets:
        print("error: nothing to hunt. Pass --filename, or run the uploader "
              "first (so the manifest has accepted uploads), or use --all.",
              file=sys.stderr)
        return 2

    if not args.quiet:
        print(f"[*] base URL : {base_url}")
        print(f"[*] hunting  : {len(targets)} file(s) across {len(dirs)} dir(s)")

    found_any = 0
    for name, data, entry in targets:
        marker = payload_marker(data) if data else None
        urls = candidate_urls(base_url, name, dirs,
                              date_dirs=not args.no_date_dirs)[:args.max_per_file]
        hit_url = None
        for url in urls:
            resp = _probe(url, headers, args)
            if confirm(resp, marker, data):
                hit_url = url
                break
            if args.delay:
                time.sleep(args.delay)
        if hit_url:
            found_any += 1
            if entry is not None and man:
                if hit_url not in entry.found_at:
                    entry.found_at.append(hit_url)
                man.save()
            if not args.quiet:
                print(f"[+] FOUND  {name:40} -> {hit_url}")
        elif not args.quiet:
            print(f"[-] miss   {name:40} ({len(urls)} probes)")

    if not args.quiet:
        print(f"\n[=] located {found_any}/{len(targets)} file(s).")
        if man and found_any:
            print("[+] stored URLs written to the manifest (found_at).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
