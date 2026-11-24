"""Integration tests for the four auxiliary tools against a local server."""
import json
import os

from upload_arsenal.manifest import Manifest, callback_token
from upload_arsenal.helpers import uploader, hunter, export_req, callback


def _request_txt(tmp_path, base_url):
    """A request.txt as copied from a proxy, pointed at the local server."""
    from urllib.parse import urlsplit
    u = urlsplit(base_url)
    raw = (
        f"POST /upload HTTP/1.1\r\n"
        f"Host: {u.netloc}\r\n"
        f"Cookie: session=abc123; csrf=tok\r\n"
        f"Authorization: Bearer XYZ\r\n"
        f"Content-Type: multipart/form-data; boundary=B0UND\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
        f"--B0UND\r\n"
        f'Content-Disposition: form-data; name="csrf"\r\n\r\ntok\r\n'
        f"--B0UND\r\n"
        f'Content-Disposition: form-data; name="file"; filename="a.jpg"\r\n'
        f"Content-Type: image/jpeg\r\n\r\nOLD\r\n"
        f"--B0UND--\r\n"
    )
    p = tmp_path / "request.txt"
    p.write_text(raw)
    return str(p)


# --------------------------------------------------------------------------- #
# Uploader
# --------------------------------------------------------------------------- #
def test_uploader_sends_and_records(suite, http_server, tmp_path):
    req = _request_txt(tmp_path, http_server.base)
    rc = uploader.main(["-m", str(suite), "-r", req, "--risk", "safe",
                        "--scheme", "http", "-q"])
    assert rc == 0
    # the server received uploads carrying the captured auth
    assert http_server.requests
    first = http_server.requests[0]
    assert "cookie" in first["headers"]
    assert first["headers"]["authorization"] == "Bearer XYZ"
    assert first["path"] == "/upload"
    # non-file csrf field preserved
    assert b'name="csrf"' in first["body"]
    # results written back into the manifest + a report produced
    man = Manifest.load(str(suite))
    assert any(e.result.get("verdict") == "accepted" for e in man.entries)
    report = json.loads((suite / "upload_results.json").read_text())
    assert report["counts"]["accepted"] > 0
    assert (suite / "upload_results.html").exists()


def test_uploader_rejection_classified(suite, http_server, tmp_path):
    http_server.behaviour = "reject"
    req = _request_txt(tmp_path, http_server.base)
    rc = uploader.main(["-m", str(suite), "-r", req, "--risk", "safe",
                        "--scheme", "http", "--fail-regex", "not allowed", "-q"])
    assert rc == 0
    man = Manifest.load(str(suite))
    assert all(e.result.get("verdict") == "rejected"
               for e in man.entries if e.result)


def test_uploader_dry_run_sends_nothing(suite, http_server, tmp_path):
    req = _request_txt(tmp_path, http_server.base)
    uploader.main(["-m", str(suite), "-r", req, "--dry-run", "-q"])
    assert http_server.requests == []


# --------------------------------------------------------------------------- #
# Hunter
# --------------------------------------------------------------------------- #
def test_hunter_locates_stored_file(suite, http_server, tmp_path):
    # pre-store a PoC payload under uploads/ so a GET finds it
    man = Manifest.load(str(suite))
    entry = next(e for e in man.entries
                 if e.path.endswith("poc.php.php") or "poc" in e.path)
    data = man.read_bytes(entry)
    name = os.path.basename(entry.path)
    http_server.stored[name] = data            # served at /uploads/<name>
    rc = hunter.main(["-m", str(suite),
                      "--base-url", http_server.base + "uploads/",
                      "--filename", name, "-q"])
    assert rc == 0
    man2 = Manifest.load(str(suite))
    e2 = man2.by_path(entry.path)
    assert any(name in url for url in e2.found_at)


# --------------------------------------------------------------------------- #
# Exporter
# --------------------------------------------------------------------------- #
def test_export_req_writes_files(suite, tmp_path):
    req = _request_txt(tmp_path, "http://t.example/")
    out = tmp_path / "reqs"
    rc = export_req.main(["-m", str(suite), "-r", req, "-o", str(out),
                          "--risk", "safe", "--ffuf-template", "--curl", "-q"])
    assert rc == 0
    reqs = list(out.glob("*.req"))
    assert reqs
    sample = reqs[0].read_bytes()
    assert sample.startswith(b"POST /upload HTTP/1.1\r\n")
    assert b"Authorization: Bearer XYZ" in sample
    assert b"name=\"file\"" in sample
    assert (out / "upload_FUZZ.req").exists()
    assert (out / "payloads.txt").exists()
    assert (out / "replay.sh").exists()
    assert (out / "INDEX.txt").exists()
    assert b"FUZZ" in (out / "upload_FUZZ.req").read_bytes()


# --------------------------------------------------------------------------- #
# Callback (arming + hit matching, no network)
# --------------------------------------------------------------------------- #
def test_callback_arm_injects_tokens(suite):
    man = Manifest.load(str(suite))
    n = callback.arm_manifest(man, "cb.example:8000",
                              dns_domain=None, quiet=True)
    assert n > 0
    # an OOB payload now points at the callback host with its token
    xxe = next(e for e in man.entries if e.category == "xxe")
    body = man.read_bytes(xxe).decode("utf-8", "surrogateescape")
    assert "cb.example:8000" in body
    assert callback_token(xxe) in body


def test_callback_registry_matches_token_hit(suite):
    man = Manifest.load(str(suite))
    callback.arm_manifest(man, "cb.example", dns_domain=None, quiet=True)
    reg = callback.Registry(man, logfile=None)
    xxe = next(e for e in man.entries if e.category == "xxe")
    tok = callback_token(xxe)
    matched = reg.record("http", {"source": "1.2.3.4",
                                  "path": f"/{tok}/xxe-ssrf"})
    assert matched is not None and matched.path == xxe.path
    man2_entry = man.by_path(xxe.path)
    assert man2_entry.callback.get("count") == 1


def test_callback_registry_path_fallback(suite):
    man = Manifest.load(str(suite))
    reg = callback.Registry(man, logfile=None)   # un-armed
    matched = reg.record("http", {"source": "1.2.3.4", "path": "/svg-ssrf"})
    assert matched is not None
    assert matched.technique == "svg-xxe"


def test_callback_dns_rejected_with_ngrok(suite, monkeypatch, capsys):
    import pytest
    monkeypatch.setattr(callback, "ngrok_public_url",
                        lambda *a, **k: "https://abcd.ngrok.app")
    with pytest.raises(SystemExit):
        callback.main(["-m", str(suite), "--use-ngrok", "--dns", "-q"])
