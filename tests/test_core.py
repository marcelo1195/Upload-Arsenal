import pytest

from upload_arsenal import core, generator


def make_ctx(profile="bugbounty", target="generic", **kw):
    return core.Context(
        profile=core.PROFILES[profile], target=core.TARGETS[target],
        languages=core.TARGETS[target].languages, **kw,
    )


def test_profiles_and_targets_present():
    assert set(core.PROFILES) == {"bugbounty", "pentest", "ctf"}
    assert "apache-php" in core.TARGETS and "generic" in core.TARGETS


def test_registry_has_techniques():
    names = {t.name for t in core.all_techniques()}
    for expected in ("poc", "rce", "revshell", "extension-bypass", "polyglot",
                     "svg-xss", "xxe", "zip-slip", "imagemagick", "param-fuzz"):
        assert expected in names


def test_bugbounty_is_safe_only():
    res = generator.run(make_ctx("bugbounty"))
    assert res.artifacts
    assert all(a.risk == "safe" for a in res.artifacts)


def test_pentest_allows_active_not_destructive():
    res = generator.run(make_ctx("pentest", lhost="10.0.0.1", lport=4444))
    risks = {a.risk for a in res.artifacts}
    assert "active" in risks
    assert "destructive" not in risks


def test_ctf_allows_destructive():
    res = generator.run(make_ctx("ctf", lhost="10.0.0.1", lport=4444))
    assert any(a.risk == "destructive" for a in res.artifacts)


def test_revshell_skipped_without_listener():
    res = generator.run(make_ctx("pentest"))
    assert not any(a.technique == "revshell" for a in res.artifacts)


def test_revshell_emitted_with_listener():
    res = generator.run(make_ctx("pentest", lhost="10.0.0.1", lport=4444))
    shells = [a for a in res.artifacts if a.technique == "revshell"]
    assert shells
    assert all(b"10.0.0.1" in a.data for a in shells)


def test_no_duplicate_paths():
    res = generator.run(make_ctx("ctf", lhost="1.2.3.4", lport=9001))
    paths = [a.relpath for a in res.artifacts]
    assert len(paths) == len(set(paths))


def test_artifact_rejects_bad_risk():
    with pytest.raises(ValueError):
        core.Artifact("x", b"x", "t", "c", "nope", "d")
