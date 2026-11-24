"""Filter-bypass artifacts: extension mangling, Content-Type, magic-byte
disguises and double extensions. These are fuzzing inputs, not executable
payloads, so they are all `safe`."""
from __future__ import annotations

from ..core import register, Context, Artifact
from .. import payloads

# Characters known to confuse upload filters / web servers.
BYPASS_CHARS_SMALL = ["", "%00", ".", "%20", "/"]
BYPASS_CHARS_MED = BYPASS_CHARS_SMALL + ["%0a", "%0d", "%0d%0a", "%09", "..", ".\\"]
BYPASS_CHARS_LARGE = BYPASS_CHARS_MED + ["…", ":", ";", "%2e", "%252e", "::$DATA"]

EXT_BY_LANG = {
    "php": [".php", ".php5", ".php7", ".phtml", ".phar", ".pht", ".inc", ".phps"],
    "aspx": [".aspx", ".asp", ".ashx", ".asax", ".config", ".cshtml"],
    "java": [".jsp", ".jspx", ".jspf", ".jsw", ".war"],
    "python": [".py", ".pyc", ".pyw"],
    "ruby": [".rb", ".rbw", ".erb"],
    "nodejs": [".js", ".mjs", ".cjs"],
}

# Common image extensions used in double-extension tricks.
DECOY_EXT = ["jpg", "png", "gif"]


def _chars(size: str) -> list[str]:
    return {"small": BYPASS_CHARS_SMALL,
            "medium": BYPASS_CHARS_MED,
            "large": BYPASS_CHARS_LARGE}.get(size, BYPASS_CHARS_MED)


@register("extension-bypass", category="filter-bypass", risk="safe",
          description="Filename/extension mangling wordlist for filter bypass.",
          reference="CWE-434")
def extension_bypass(ctx: Context):
    chars = _chars(ctx.wordlist_size)
    trailing = list(ctx.target.trailing) or chars
    for lang in ctx.langs():
        exts = EXT_BY_LANG.get(lang) or EXT_BY_LANG.get(ctx.target.name.split("-")[-1])
        if not exts:
            continue
        seen: set[str] = set()
        lines: list[str] = []

        def add(name: str):
            if name not in seen:
                seen.add(name)
                lines.append(name)

        for ext in exts:
            base = "shell"
            add(f"{base}{ext}")
            add(f"{base}{ext.upper()}")
            # case mangling (pHp)
            add(f"{base}{ext[:2]}{ext[2:].upper()}")
            # trailing chars
            for c in trailing:
                add(f"{base}{ext}{c}")
                add(f"{base}{c}{ext}")
            # double extension / decoy
            for decoy in DECOY_EXT:
                add(f"{base}{ext}.{decoy}")
                add(f"{base}.{decoy}{ext}")
                add(f"{base}.{decoy}%00{ext}")
            # char-injected variants (bounded)
            for c in chars:
                if c:
                    add(f"{base}{c}{ext}")
                    add(f"{base}{ext}{c}")

        data = "\n".join(lines) + "\n"
        yield Artifact(
            relpath=f"{lang}/wordlists/extension_bypass.txt",
            data=data, technique="extension-bypass", category="filter-bypass",
            risk="safe", language=lang,
            description=f"{len(lines)} filename variants for {lang}.",
            usage="Feed to Burp Intruder / ffuf as the filename field.",
            reference="CWE-434",
        )


# Curated, high-signal image MIME types (not the exhaustive IANA dump).
MIME_TYPES = [
    "image/png", "image/jpeg", "image/jpg", "image/pjpeg", "image/gif",
    "image/bmp", "image/webp", "image/x-icon", "image/vnd.microsoft.icon",
    "image/svg+xml", "image/tiff", "image/heic", "image/avif",
    "application/octet-stream", "text/plain",
]


@register("content-type", category="filter-bypass", risk="safe",
          description="Content-Type values to fuzz MIME validation.",
          reference="CWE-434")
def content_type(ctx: Context):
    data = "\n".join(MIME_TYPES) + "\n"
    yield Artifact(
        relpath="wordlists/content_type.txt", data=data,
        technique="content-type", category="filter-bypass", risk="safe",
        description=f"{len(MIME_TYPES)} Content-Type values.",
        usage="Fuzz the multipart Content-Type header of the upload part.",
        reference="CWE-434",
    )
