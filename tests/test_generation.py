import json
import os
import zipfile

from upload_arsenal import core, generator


def _ctx(profile="ctf", target="generic"):
    return core.Context(
        profile=core.PROFILES[profile], target=core.TARGETS[target],
        languages=core.TARGETS[target].languages, lhost="10.0.0.1", lport=4444,
    )


def test_write_produces_manifest_and_report(tmp_path):
    res = generator.run(_ctx())
    generator.write(res, str(tmp_path))
    assert (tmp_path / "index.json").exists()
    assert (tmp_path / "index.md").exists()
    assert (tmp_path / "report.html").exists()
    meta = json.loads((tmp_path / "index.json").read_text())
    assert meta["meta"]["count"] == len(res.artifacts)
    assert len(meta["artifacts"]) == len(res.artifacts)


def test_polyglots_have_valid_headers(tmp_path):
    res = generator.run(_ctx())
    generator.write(res, str(tmp_path))
    png = tmp_path / "php" / "polyglots" / "poc.php.png"
    assert png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    gif = tmp_path / "php" / "polyglots" / "poc.php.gif"
    assert gif.read_bytes()[:6] == b"GIF89a"


def test_zipslip_entries_escape(tmp_path):
    res = generator.run(_ctx())
    generator.write(res, str(tmp_path))
    with zipfile.ZipFile(tmp_path / "archives" / "zipslip.zip") as zf:
        assert any(".." in n for n in zf.namelist())


def test_apache_php_target_only_php(tmp_path):
    ctx = core.Context(
        profile=core.PROFILES["bugbounty"], target=core.TARGETS["apache-php"],
        languages=core.TARGETS["apache-php"].languages,
    )
    res = generator.run(ctx)
    langs = {a.language for a in res.artifacts if a.language}
    assert langs <= {"php"}


def test_server_side_targets_emit_executable_poc(tmp_path):
    """Regression: the IIS and Tomcat sinks must emit a code-exec PoC in their
    native server-side syntax, not a non-executable class saved with a .jsp/
    .aspx name (and IIS previously emitted no code payload at all)."""
    expected = {
        "iis-aspnet": ("aspx", "Response.Write"),
        "tomcat-java": ("jsp", "out.println"),
    }
    for target, (lang, needle) in expected.items():
        ctx = core.Context(
            profile=core.PROFILES["bugbounty"], target=core.TARGETS[target],
            languages=core.TARGETS[target].languages,
        )
        res = generator.run(ctx)
        pocs = [a for a in res.artifacts if a.technique == "poc"]
        assert pocs, f"{target} emitted no PoC payload"
        assert {a.language for a in pocs} == {lang}
        body = pocs[0].data.decode("utf-8", "replace")
        assert needle in body
        assert "code execution confirmed" in body


def test_only_filter(tmp_path):
    ctx = _ctx()
    res = generator.run(ctx, only={"param-fuzz"})
    assert {a.technique for a in res.artifacts} == {"param-fuzz"}


def test_fuzz_wordlists_present():
    res = generator.run(_ctx())
    paths = {a.relpath for a in res.artifacts}
    for name in ("param_names.txt", "filenames.txt", "path_traversal.txt",
                 "ssrf_urls.txt"):
        assert f"wordlists/fuzz/{name}" in paths
