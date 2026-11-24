"""Tests for raw request parsing, multipart rebuilding and serialisation."""
import pytest

from upload_arsenal import rawhttp


BURP_MULTIPART = (
    "POST /api/upload?token=abc HTTP/2\r\n"
    "Host: target.example\r\n"
    "Cookie: session=deadbeef; csrf=zzz\r\n"
    "Authorization: Bearer SECRET-TOKEN-VALUE\r\n"
    "User-Agent: Mozilla/5.0\r\n"
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryAbC123\r\n"
    "Content-Length: 9999\r\n"
    "\r\n"
    "------WebKitFormBoundaryAbC123\r\n"
    'Content-Disposition: form-data; name="csrf"\r\n'
    "\r\n"
    "zzz\r\n"
    "------WebKitFormBoundaryAbC123\r\n"
    'Content-Disposition: form-data; name="file"; filename="photo.jpg"\r\n'
    "Content-Type: image/jpeg\r\n"
    "\r\n"
    "ORIGINALBYTES\r\n"
    "------WebKitFormBoundaryAbC123--\r\n"
)


def test_parse_basic_fields():
    req = rawhttp.parse_raw_request(BURP_MULTIPART)
    assert req.method == "POST"
    assert req.target == "/api/upload?token=abc"
    assert req.host == "target.example"
    assert req.port == 443
    assert req.scheme == "https"
    assert req.get_header("Authorization") == "Bearer SECRET-TOKEN-VALUE"


def test_parse_cookies_and_auth_summary():
    req = rawhttp.parse_raw_request(BURP_MULTIPART)
    jar = req.cookies()
    assert jar == {"session": "deadbeef", "csrf": "zzz"}
    summary = " ".join(rawhttp.describe_auth(req))
    assert "Bearer" in summary
    assert "SECRET-TOKEN-VALUE" not in summary  # masked
    assert "anti-CSRF" in summary                # csrf form field detected


def test_multipart_detection_and_boundary():
    req = rawhttp.parse_raw_request(BURP_MULTIPART)
    assert req.is_multipart
    assert req.boundary == "----WebKitFormBoundaryAbC123"
    files = rawhttp.file_parts(req)
    assert [p.name for p in files] == ["file"]
    assert files[0].filename == "photo.jpg"


def test_template_renders_new_payload():
    req = rawhttp.parse_raw_request(BURP_MULTIPART)
    tmpl = rawhttp.UploadTemplate.from_request(req)
    out = tmpl.render(b"<?php echo 1;?>", "shell.php", content_type="guess")
    parts = rawhttp.parse_multipart(out.body, out.boundary)
    fp = next(p for p in parts if p.name == "file")
    assert fp.filename == "shell.php"
    assert fp.data == b"<?php echo 1;?>"
    # non-file field preserved untouched (auth/csrf survives)
    csrf = next(p for p in parts if p.name == "csrf")
    assert csrf.data == b"zzz"


def test_template_rejects_ambiguous_field():
    body = BURP_MULTIPART.replace(
        'name="csrf"',
        'name="file2"; filename="other.png"')
    req = rawhttp.parse_raw_request(body)
    with pytest.raises(rawhttp.RawRequestError):
        rawhttp.UploadTemplate.from_request(req)  # two file parts, no --field
    tmpl = rawhttp.UploadTemplate.from_request(req, field="file")
    assert tmpl.field == "file"


def test_lf_only_and_absolute_target():
    raw = ("POST http://host.example:8080/up HTTP/1.1\n"
           "Host: host.example:8080\n"
           "Content-Type: application/octet-stream\n"
           "\n"
           "RAWDATA")
    req = rawhttp.parse_raw_request(raw)
    assert req.host == "host.example" and req.port == 8080
    assert req.target == "/up"
    assert req.body == b"RAWDATA"
    assert not req.is_multipart


def test_raw_body_template():
    raw = ("PUT /files/x.bin HTTP/1.1\r\nHost: h\r\n"
           "Content-Type: application/octet-stream\r\n\r\nOLD")
    req = rawhttp.parse_raw_request(raw)
    tmpl = rawhttp.UploadTemplate.from_request(req, raw_body=True)
    out = tmpl.render(b"NEWBYTES", "x.bin", content_type="keep")
    assert out.body == b"NEWBYTES"


def test_to_bytes_roundtrip_sets_content_length():
    req = rawhttp.parse_raw_request(BURP_MULTIPART)
    tmpl = rawhttp.UploadTemplate.from_request(req)
    out = tmpl.render(b"AAA", "a.php")
    raw = out.to_bytes()
    assert raw.startswith(b"POST /api/upload?token=abc HTTP/1.1\r\n")
    cl = out.get_header  # content-length recomputed in to_bytes, not stored
    assert b"Content-Length: %d" % len(out.body) in raw
    assert b"HTTP/2" not in raw  # downgraded
