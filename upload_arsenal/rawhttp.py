"""Raw HTTP request handling shared by the helper tools.

Parses a request copied verbatim from an intercepting proxy (Burp Suite's
"Copy to file" / "Copy request", Caido's raw view, ZAP, mitmproxy), rebuilds
multipart bodies with a new file part, serialises requests back to raw form,
and sends them with the standard library while preserving header order.

Everything here is dependency-free on purpose: the tool has no runtime deps.
"""
from __future__ import annotations

import gzip
import http.client
import mimetypes
import os
import re
import socket
import ssl
import time
import zlib
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# Headers we always recompute or must not forward verbatim.
_HOP_HEADERS = {"content-length", "transfer-encoding", "connection",
                "proxy-connection", "keep-alive"}


class RawRequestError(ValueError):
    """Raised when a raw request cannot be parsed or used as a template."""


# --------------------------------------------------------------------------- #
# Request model
# --------------------------------------------------------------------------- #
@dataclass
class RawRequest:
    method: str
    target: str                       # path + query, e.g. "/api/upload?x=1"
    version: str = "HTTP/1.1"
    headers: list = field(default_factory=list)   # [(name, value)], order kept
    body: bytes = b""
    scheme: str = "https"
    host: str = ""
    port: int = 443

    # ---- header helpers (case-insensitive, order-preserving) ---------------
    def get_header(self, name: str, default: str | None = None) -> str | None:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return default

    def set_header(self, name: str, value: str) -> None:
        """Replace the first occurrence (dropping duplicates) or append."""
        low = name.lower()
        out, done = [], False
        for k, v in self.headers:
            if k.lower() == low:
                if not done:
                    out.append((k, value))
                    done = True
                continue
            out.append((k, v))
        if not done:
            out.append((name, value))
        self.headers = out

    def remove_header(self, name: str) -> None:
        low = name.lower()
        self.headers = [(k, v) for k, v in self.headers if k.lower() != low]

    # ---- derived properties -------------------------------------------------
    @property
    def authority(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.authority}{self.target}"

    @property
    def content_type(self) -> str:
        return self.get_header("Content-Type", "") or ""

    @property
    def boundary(self) -> str | None:
        m = re.search(r'boundary=("?)([^";]+)\1', self.content_type, re.I)
        return m.group(2) if m else None

    @property
    def is_multipart(self) -> bool:
        return self.content_type.lower().startswith("multipart/") and bool(self.boundary)

    def cookies(self) -> dict:
        """Cookies from every Cookie header, in order."""
        jar: dict = {}
        for k, v in self.headers:
            if k.lower() != "cookie":
                continue
            for pair in v.split(";"):
                if "=" in pair:
                    n, _, val = pair.strip().partition("=")
                    jar[n] = val
        return jar

    def copy(self) -> "RawRequest":
        return RawRequest(self.method, self.target, self.version,
                          list(self.headers), self.body, self.scheme,
                          self.host, self.port)

    # ---- serialisation -----------------------------------------------------
    def to_bytes(self, *, version: str | None = None) -> bytes:
        """Raw HTTP/1.1 bytes (CRLF), suitable for Burp Repeater or ffuf."""
        ver = version or "HTTP/1.1"
        if ver.upper().startswith("HTTP/2"):
            ver = "HTTP/1.1"
        lines = [f"{self.method} {self.target} {ver}"]
        has_host = any(k.lower() == "host" for k, _ in self.headers)
        if not has_host:
            lines.append(f"Host: {self.authority}")
        for k, v in self.headers:
            if k.lower() in _HOP_HEADERS:
                continue
            lines.append(f"{k}: {v}")
        if self.body or self.method.upper() in ("POST", "PUT", "PATCH"):
            lines.append(f"Content-Length: {len(self.body)}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + self.body


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _split_head_body(data: bytes) -> tuple[bytes, bytes, bool]:
    """Split at the first blank line. Returns (head, body, crlf_used)."""
    crlf = data.find(b"\r\n\r\n")
    lf = data.find(b"\n\n")
    if crlf != -1 and (lf == -1 or crlf <= lf):
        return data[:crlf], data[crlf + 4:], True
    if lf != -1:
        return data[:lf], data[lf + 2:], False
    return data, b"", b"\r\n" in data


def parse_raw_request(data: bytes | str, *, scheme: str | None = None,
                      default_scheme: str = "https") -> RawRequest:
    """Parse a raw request as copied from Burp/Caido.

    Tolerates LF-only line endings (common after pasting into an editor),
    absolute-form request targets, HTTP/2 pseudo-headers (``:authority``),
    folded header lines and a leading BOM/blank lines.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogateescape")
    data = data.lstrip(b"\xef\xbb\xbf").lstrip(b"\r\n \t")
    if not data:
        raise RawRequestError("empty request")
    head, body, _ = _split_head_body(data)
    lines = re.split(rb"\r?\n", head)

    parts = lines[0].decode("latin-1").split()
    if len(parts) < 2:
        raise RawRequestError(f"bad request line: {lines[0][:80]!r}")
    method, target = parts[0].upper(), parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"

    headers: list = []
    pseudo: dict = {}
    for raw in lines[1:]:
        line = raw.decode("latin-1")
        if not line.strip():
            continue
        if line[0] in " \t" and headers:          # obs-fold continuation
            k, v = headers[-1]
            headers[-1] = (k, v + " " + line.strip())
            continue
        if line.startswith(":"):                  # HTTP/2 pseudo-header
            name, _, value = line[1:].partition(":")
            pseudo[name.strip().lower()] = value.strip()
            continue
        name, sep, value = line.partition(":")
        if not sep:
            raise RawRequestError(f"bad header line: {line[:80]!r}")
        headers.append((name.strip(), value.strip()))

    req = RawRequest(method=method, target=target, version=version,
                     headers=headers, body=body)

    # Resolve scheme / host / port.
    if target.lower().startswith(("http://", "https://")):
        u = urlsplit(target)
        req.scheme = u.scheme.lower()
        req.target = (u.path or "/") + (f"?{u.query}" if u.query else "")
        hostport = u.netloc
    else:
        req.scheme = (scheme or pseudo.get("scheme") or default_scheme).lower()
        hostport = req.get_header("Host") or pseudo.get("authority") or ""
    if scheme:
        req.scheme = scheme.lower()
    if not hostport:
        raise RawRequestError("no Host header and no absolute URL in request line")
    if not req.get_header("Host"):
        req.headers.insert(0, ("Host", hostport))
    host, port = split_hostport(hostport, req.scheme)
    req.host, req.port = host, port
    return req


def split_hostport(hostport: str, scheme: str) -> tuple[str, int]:
    default = 443 if scheme == "https" else 80
    if hostport.startswith("["):                  # IPv6 literal
        end = hostport.find("]")
        host = hostport[1:end]
        rest = hostport[end + 1:]
        return host, int(rest[1:]) if rest.startswith(":") else default
    if hostport.count(":") == 1:
        h, p = hostport.split(":")
        if p.isdigit():
            return h, int(p)
    return hostport, default


def load_request_file(path: str, **kw) -> RawRequest:
    with open(path, "rb") as f:
        return parse_raw_request(f.read(), **kw)


# --------------------------------------------------------------------------- #
# Multipart
# --------------------------------------------------------------------------- #
_PARAM_RE = re.compile(r';\s*([A-Za-z0-9_\-\*]+)\s*=\s*("((?:[^"\\]|\\.)*)"|[^;]*)')


def parse_disposition(value: str) -> dict:
    """Parse a Content-Disposition value into {'type': ..., param: value}."""
    out = {"type": value.split(";", 1)[0].strip().lower()}
    for m in _PARAM_RE.finditer(value):
        key = m.group(1).lower()
        out[key] = m.group(3) if m.group(3) is not None else m.group(2).strip()
    return out


@dataclass
class Part:
    headers: list = field(default_factory=list)   # [(name, value)]
    data: bytes = b""

    def get_header(self, name: str, default: str | None = None) -> str | None:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return default

    def set_header(self, name: str, value: str) -> None:
        for i, (k, _) in enumerate(self.headers):
            if k.lower() == name.lower():
                self.headers[i] = (k, value)
                return
        self.headers.append((name, value))

    @property
    def disposition(self) -> dict:
        return parse_disposition(self.get_header("Content-Disposition", "") or "")

    @property
    def name(self) -> str | None:
        return self.disposition.get("name")

    @property
    def filename(self) -> str | None:
        d = self.disposition
        return d.get("filename", d.get("filename*"))

    @property
    def is_file(self) -> bool:
        d = self.disposition
        return "filename" in d or "filename*" in d

    def set_filename(self, filename: str) -> None:
        """Rewrite the filename parameter, keeping every other parameter."""
        cd = self.get_header("Content-Disposition", "form-data") or "form-data"
        cd = re.sub(r';\s*filename\*\s*=\s*("(?:[^"\\]|\\.)*"|[^;]*)', "", cd)
        quoted = filename.replace("\\", "\\\\").replace('"', '\\"')
        if re.search(r';\s*filename\s*=', cd):
            cd = re.sub(r'(;\s*filename\s*=\s*)("(?:[^"\\]|\\.)*"|[^;]*)',
                        lambda m: f'{m.group(1)}"{quoted}"', cd, count=1)
        else:
            cd += f'; filename="{quoted}"'
        self.set_header("Content-Disposition", cd)


def parse_multipart(body: bytes, boundary: str) -> list[Part]:
    """Split a multipart body. Tolerant of LF-only line endings."""
    delim = b"--" + boundary.encode("latin-1")
    chunks = body.split(delim)
    parts: list[Part] = []
    for chunk in chunks[1:]:
        if chunk.startswith(b"--"):
            break                                 # closing delimiter
        # strip the line break right after the delimiter
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        elif chunk.startswith(b"\n"):
            chunk = chunk[1:]
        # strip the line break that precedes the next delimiter
        if chunk.endswith(b"\r\n"):
            chunk = chunk[:-2]
        elif chunk.endswith(b"\n"):
            chunk = chunk[:-1]
        head, data, _ = _split_head_body(chunk)
        hdrs = []
        for raw in re.split(rb"\r?\n", head):
            line = raw.decode("utf-8", "surrogateescape")
            if not line.strip():
                continue
            name, _, value = line.partition(":")
            hdrs.append((name.strip(), value.strip()))
        parts.append(Part(headers=hdrs, data=data))
    if not parts:
        raise RawRequestError("multipart body has no parts for the given boundary")
    return parts


def boundary_collides(parts: list[Part], boundary: str) -> bool:
    """True if any part's body contains the delimiter, which would corrupt it."""
    delim = b"--" + boundary.encode("latin-1")
    return any(delim in p.data for p in parts)


def fresh_boundary(parts: list[Part]) -> str:
    """A boundary that appears in no part body."""
    while True:
        cand = "----uploadArsenal" + os.urandom(12).hex()
        if not boundary_collides(parts, cand):
            return cand


def build_multipart(parts: list[Part], boundary: str) -> bytes:
    out = bytearray()
    b = boundary.encode("latin-1")
    for p in parts:
        out += b"--" + b + b"\r\n"
        for k, v in p.headers:
            out += f"{k}: {v}".encode("utf-8", "surrogateescape") + b"\r\n"
        out += b"\r\n" + p.data + b"\r\n"
    out += b"--" + b + b"--\r\n"
    return bytes(out)


def file_parts(req: RawRequest) -> list[Part]:
    if not req.is_multipart:
        return []
    return [p for p in parse_multipart(req.body, req.boundary) if p.is_file]


def guess_mime(filename: str) -> str:
    # strip junk appended by filter-bypass names ("shell.php%00.jpg" etc.)
    clean = re.sub(r"(%00|%20|%0a|%0d|::\$DATA)", "", filename)
    mime, _ = mimetypes.guess_type(clean, strict=False)
    return mime or "application/octet-stream"


# --------------------------------------------------------------------------- #
# Template: a request with one file slot to fill
# --------------------------------------------------------------------------- #
@dataclass
class UploadTemplate:
    """A parsed request plus the location of the file slot to replace."""
    request: RawRequest
    field: str | None = None          # multipart field name; None for raw body

    @classmethod
    def from_request(cls, req: RawRequest, field: str | None = None,
                     raw_body: bool = False) -> "UploadTemplate":
        if raw_body or not req.is_multipart:
            if field:
                raise RawRequestError(
                    "--field given but the request is not multipart/form-data")
            return cls(req, None)
        files = file_parts(req)
        if field:
            names = [p.name for p in parse_multipart(req.body, req.boundary)]
            if field not in names:
                raise RawRequestError(
                    f"field {field!r} not found; multipart fields: {names}")
            return cls(req, field)
        if not files:
            raise RawRequestError(
                "multipart request has no part with a filename=; pass --field "
                "to choose which part to replace")
        if len(files) > 1:
            names = [p.name for p in files]
            raise RawRequestError(
                f"several file parts {names}; pass --field to choose one")
        return cls(req, files[0].name)

    @property
    def is_multipart(self) -> bool:
        return self.field is not None

    @property
    def original_filename(self) -> str | None:
        if not self.is_multipart:
            return None
        for p in parse_multipart(self.request.body, self.request.boundary):
            if p.name == self.field:
                return p.filename
        return None

    def render(self, data: bytes, filename: str,
               content_type: str | None = "guess") -> RawRequest:
        """Return a new request with the file slot set to `data`/`filename`.

        content_type: "guess" (from filename), "keep" (template's value), or a
        literal MIME type.
        """
        req = self.request.copy()
        if not self.is_multipart:
            req.body = data
            if content_type not in (None, "keep"):
                ct = guess_mime(filename) if content_type == "guess" else content_type
                req.set_header("Content-Type", ct)
            if "{filename}" in req.target:
                req.target = req.target.replace("{filename}", filename)
            return req
        boundary = req.boundary
        parts = parse_multipart(req.body, boundary)
        for p in parts:
            if p.name == self.field:
                p.set_filename(filename)
                p.data = data
                if content_type == "guess":
                    p.set_header("Content-Type", guess_mime(filename))
                elif content_type not in (None, "keep"):
                    p.set_header("Content-Type", content_type)
                break
        # A payload whose bytes contain the captured delimiter would truncate
        # the part and inject a bogus one — the server would store a corrupt
        # file and the test would read as a false negative. Re-key the body on
        # a boundary that does not occur in any part instead.
        if boundary_collides(parts, boundary):
            boundary = fresh_boundary(parts)
            ct = re.sub(r'boundary=("?)[^";]+\1', f"boundary={boundary}",
                        req.content_type, count=1)
            if f"boundary={boundary}" not in ct:
                ct = f"{ct.split(';')[0]}; boundary={boundary}"
            req.set_header("Content-Type", ct)
        req.body = build_multipart(parts, boundary)
        return req


# --------------------------------------------------------------------------- #
# Sending
# --------------------------------------------------------------------------- #
@dataclass
class Response:
    status: int
    reason: str
    headers: list
    body: bytes
    elapsed: float
    error: str | None = None

    def get_header(self, name: str, default: str | None = None) -> str | None:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return default

    def text(self, limit: int | None = None) -> str:
        body = self.body if limit is None else self.body[:limit]
        return body.decode("utf-8", "replace")


def _decode_body(body: bytes, encoding: str | None) -> bytes:
    enc = (encoding or "").lower().strip()
    try:
        if enc == "gzip":
            return gzip.decompress(body)
        if enc == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -15)
    except (OSError, zlib.error, EOFError):
        pass
    return body


def _sanitise_accept_encoding(value: str) -> str:
    """Drop encodings we can't decode with the stdlib (br, zstd)."""
    keep = [e for e in (x.strip() for x in value.split(","))
            if e and e.split(";")[0].strip().lower() in ("gzip", "deflate", "identity")]
    return ", ".join(keep) or "identity"


def send(req: RawRequest, *, timeout: float = 20.0, proxy: str | None = None,
         verify: bool = False, follow_redirects: bool = False,
         max_redirects: int = 5) -> Response:
    """Send `req` with http.client, keeping header order.

    proxy: "http://127.0.0.1:8080" to route through Burp/Caido (HTTPS is
    tunnelled with CONNECT). verify=False skips TLS validation, which is what
    you want behind an intercepting proxy or against self-signed lab targets.
    """
    start = time.monotonic()
    try:
        resp = _send_once(req, timeout, proxy, verify)
    except (OSError, http.client.HTTPException, socket.timeout, ssl.SSLError) as e:
        return Response(0, "", [], b"", time.monotonic() - start, error=str(e) or repr(e))
    hops = 0
    while (follow_redirects and resp.status in (301, 302, 303, 307, 308)
           and hops < max_redirects and resp.get_header("Location")):
        hops += 1
        nxt = redirect_request(req, resp.get_header("Location"), resp.status)
        try:
            resp = _send_once(nxt, timeout, proxy, verify)
        except (OSError, http.client.HTTPException, ssl.SSLError) as e:
            return Response(0, "", [], b"", time.monotonic() - start, error=str(e))
        req = nxt
    resp.elapsed = time.monotonic() - start
    return resp


def redirect_request(req: RawRequest, location: str, status: int) -> RawRequest:
    nxt = req.copy()
    u = urlsplit(location)
    if u.scheme:
        nxt.scheme = u.scheme
        nxt.host, nxt.port = split_hostport(u.netloc, u.scheme)
        nxt.set_header("Host", nxt.authority)
    path = u.path or "/"
    if not path.startswith("/"):
        base = req.target.split("?", 1)[0].rsplit("/", 1)[0]
        path = f"{base}/{path}"
    nxt.target = path + (f"?{u.query}" if u.query else "")
    if status in (301, 302, 303):
        nxt.method, nxt.body = "GET", b""
        nxt.remove_header("Content-Type")
    return nxt


def _send_once(req: RawRequest, timeout: float, proxy: str | None,
               verify: bool) -> Response:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    target = req.target
    if proxy:
        pu = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
        phost, pport = split_hostport(pu.netloc, "http")
        if req.scheme == "https":
            conn = http.client.HTTPSConnection(phost, pport, timeout=timeout, context=ctx)
            conn.set_tunnel(req.host, req.port)
        else:
            conn = http.client.HTTPConnection(phost, pport, timeout=timeout)
            target = req.url                      # absolute-form for HTTP proxies
    elif req.scheme == "https":
        conn = http.client.HTTPSConnection(req.host, req.port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(req.host, req.port, timeout=timeout)

    try:
        conn.putrequest(req.method, target, skip_host=True, skip_accept_encoding=True)
        sent_host = False
        for k, v in req.headers:
            low = k.lower()
            if low in _HOP_HEADERS:
                continue
            if low == "host":
                sent_host = True
            if low == "accept-encoding":
                v = _sanitise_accept_encoding(v)
            conn.putheader(k, v)
        if not sent_host:
            conn.putheader("Host", req.authority)
        if req.body or req.method in ("POST", "PUT", "PATCH"):
            conn.putheader("Content-Length", str(len(req.body)))
        conn.endheaders(req.body or None)
        r = conn.getresponse()
        raw = r.read()
        hdrs = list(r.getheaders())
        body = _decode_body(raw, r.getheader("Content-Encoding"))
        return Response(r.status, r.reason, hdrs, body, 0.0)
    finally:
        conn.close()


def mask(value: str, keep: int = 6) -> str:
    """Mask a secret for display: keep a short prefix only."""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "…" + f"({len(value)} chars)"


def describe_auth(req: RawRequest) -> list[str]:
    """Human summary of the auth material found in the request (masked)."""
    out = []
    jar = req.cookies()
    if jar:
        out.append(f"Cookie: {len(jar)} cookie(s): " + ", ".join(jar))
    for k, v in req.headers:
        low = k.lower()
        if low == "authorization":
            scheme, _, cred = v.partition(" ")
            out.append(f"Authorization: {scheme} {mask(cred)}")
        elif low.startswith("x-") and any(t in low for t in ("token", "csrf", "xsrf",
                                                              "api-key", "apikey", "auth")):
            out.append(f"{k}: {mask(v)}")
    if req.is_multipart:
        for p in parse_multipart(req.body, req.boundary):
            if not p.is_file and p.name and re.search(r"csrf|xsrf|token|nonce", p.name, re.I):
                out.append(f"form field {p.name!r} looks like an anti-CSRF token "
                           f"(sent as-is; refresh request.txt if it expires)")
    return out
