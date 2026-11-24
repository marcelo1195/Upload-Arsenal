"""Orchestration: run the selected techniques against a context, then write
artifacts + a manifest (index.json / index.md) + an HTML report."""
from __future__ import annotations

import html
import json
import os
from dataclasses import dataclass

from . import core, __version__
from . import techniques as _techniques  # noqa: F401  (registers techniques)


@dataclass
class RunResult:
    artifacts: list
    skipped: list              # (technique, reason)
    context: core.Context


def select_techniques(ctx: core.Context, only=None, exclude_names=()):
    """Techniques allowed by the profile, optionally narrowed by name."""
    chosen, skipped = [], []
    for tech in core.all_techniques():
        if only and tech.name not in only:
            continue
        if tech.name in exclude_names:
            skipped.append((tech.name, "excluded by --exclude"))
            continue
        if not ctx.profile.accepts(tech):
            skipped.append((tech.name, f"risk/category not in '{ctx.profile.name}'"))
            continue
        chosen.append(tech)
    return chosen, skipped


def run(ctx: core.Context, only=None, exclude_names=()) -> RunResult:
    chosen, skipped = select_techniques(ctx, only, exclude_names)
    artifacts: list[core.Artifact] = []
    seen: set[str] = set()
    for tech in chosen:
        produced = 0
        for art in tech.generate(ctx):
            if art.relpath in seen:
                continue  # dedup identical paths across techniques
            seen.add(art.relpath)
            artifacts.append(art)
            produced += 1
        if produced == 0:
            skipped.append((tech.name, "produced nothing for this target/context"))
    return RunResult(artifacts=artifacts, skipped=skipped, context=ctx)


def write(result: RunResult, out_dir: str) -> None:
    for art in result.artifacts:
        dest = os.path.join(out_dir, art.relpath)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as f:
            f.write(art.data)
    _write_manifest(result, out_dir)
    _write_report(result, out_dir)


def _manifest_rows(result: RunResult):
    for art in sorted(result.artifacts, key=lambda a: a.relpath):
        yield {
            "path": art.relpath, "technique": art.technique,
            "category": art.category, "risk": art.risk,
            "language": art.language, "description": art.description,
            "usage": art.usage, "reference": art.reference,
            "bytes": len(art.data),
        }


def _write_manifest(result: RunResult, out_dir: str) -> None:
    ctx = result.context
    rows = list(_manifest_rows(result))
    meta = {
        "tool": "upload-arsenal", "version": __version__,
        "profile": ctx.profile.name, "target": ctx.target.name,
        "languages": list(ctx.langs()), "obfuscated": ctx.obfuscate,
        "lhost": ctx.lhost, "lport": ctx.lport, "count": len(rows),
    }
    with open(os.path.join(out_dir, "index.json"), "w") as f:
        json.dump({"meta": meta, "artifacts": rows}, f, indent=2)

    lines = [
        f"# Upload Arsenal — generated suite (v{__version__})", "",
        f"- **Profile:** `{ctx.profile.name}` — {ctx.profile.description}",
        f"- **Target:** `{ctx.target.name}` — {ctx.target.description}",
        f"- **Languages:** {', '.join(ctx.langs())}",
        f"- **Obfuscated:** {ctx.obfuscate}",
    ]
    if ctx.lhost:
        lines.append(f"- **LHOST:LPORT:** {ctx.lhost}:{ctx.lport}")
    lines += ["", f"**{len(rows)} artifacts.**", ""]
    lines += ["| File | Technique | Risk | Tests | Usage |",
              "|------|-----------|------|-------|-------|"]
    for r in rows:
        lines.append(
            f"| `{r['path']}` | {r['technique']} | {r['risk']} | "
            f"{r['description']} | {r['usage']} |"
        )
    if result.skipped:
        lines += ["", "## Skipped", ""]
        for name, why in result.skipped:
            lines.append(f"- `{name}` — {why}")
    with open(os.path.join(out_dir, "index.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


_RISK_COLOR = {"safe": "#2e7d32", "active": "#ef6c00", "destructive": "#c62828"}


def _write_report(result: RunResult, out_dir: str) -> None:
    ctx = result.context
    rows = list(_manifest_rows(result))
    tr = "\n".join(
        "<tr>"
        f"<td><code>{html.escape(r['path'])}</code></td>"
        f"<td>{html.escape(r['technique'])}</td>"
        f"<td><span style='color:{_RISK_COLOR.get(r['risk'], '#555')}'>"
        f"{r['risk']}</span></td>"
        f"<td>{html.escape(r['description'])}</td>"
        f"<td>{html.escape(r['usage'])}</td>"
        f"<td>{html.escape(r['reference'])}</td>"
        "</tr>"
        for r in rows
    )
    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Upload Arsenal report</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#222}}
 h1{{margin-bottom:.2rem}} .meta{{color:#555;margin-bottom:1rem}}
 table{{border-collapse:collapse;width:100%}}
 th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}}
 th{{background:#f5f5f5}} code{{background:#f0f0f0;padding:0 .2rem;border-radius:3px}}
</style></head><body>
<h1>Upload Arsenal report</h1>
<div class="meta">
 Profile <b>{html.escape(ctx.profile.name)}</b> ·
 Target <b>{html.escape(ctx.target.name)}</b> ·
 Languages {html.escape(', '.join(ctx.langs()))} ·
 Obfuscated {ctx.obfuscate} ·
 {len(rows)} artifacts
</div>
<table><thead><tr>
 <th>File</th><th>Technique</th><th>Risk</th><th>Tests</th><th>Usage</th><th>Ref</th>
</tr></thead><tbody>
{tr}
</tbody></table>
</body></html>"""
    with open(os.path.join(out_dir, "report.html"), "w") as f:
        f.write(doc)
