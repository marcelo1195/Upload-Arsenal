"""Shared helpers for technique modules."""
from __future__ import annotations

from ..core import Artifact, Context
from .. import payloads


def maybe_obf(ctx: Context, language: str, code: str) -> str:
    return payloads.obfuscate(language, code) if ctx.obfuscate else code


def code_artifact(ctx: Context, language: str, extension: str, kind: str,
                  code: str, *, category: str, risk: str, description: str,
                  usage: str = "", reference: str = "") -> Artifact:
    """Build a code-payload artifact, applying obfuscation + a magic-bytes
    prefix when the extension is an image/doc type."""
    body = maybe_obf(ctx, language, code).encode()
    prefix = payloads.magic_for(extension)
    data = (prefix + b"\n" + body) if prefix else body
    relpath = f"{language}/{kind}.{language}.{extension}"
    return Artifact(
        relpath=relpath, data=data, technique=kind, category=category,
        risk=risk, description=description, usage=usage, reference=reference,
        language=language,
    )
