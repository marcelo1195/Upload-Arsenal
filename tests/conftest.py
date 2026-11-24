"""Shared fixtures: a generated suite and a local HTTP server."""
import http.server
import socketserver
import threading

import pytest

from upload_arsenal import core, generator


@pytest.fixture
def suite(tmp_path):
    """Generate a real pentest suite into tmp_path and return its dir."""
    ctx = core.Context(
        profile=core.PROFILES["pentest"], target=core.TARGETS["apache-php"],
        languages=core.TARGETS["apache-php"].languages,
        lhost="10.0.0.1", lport=4444, callback_host="ATTACKER_HOST",
    )
    res = generator.run(ctx)
    generator.write(res, str(tmp_path / "suite"))
    return tmp_path / "suite"


class _RecordingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    requests = None
    behaviour = "accept"          # accept | reject | echo
    stored = None                 # dict filename -> bytes, for the hunter


def _make_handler():
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            self.server.requests.append({
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body,
            })
            # remember a "stored" copy keyed by the filename in the part
            import re
            m = re.search(rb'filename="([^"]+)"', body)
            if m and self.server.stored is not None:
                fn = m.group(1).decode()
                # crude: take bytes after the double CRLF following that header
                self.server.stored[fn] = body
            if self.server.behaviour == "reject":
                self._reply(403, b"file type not allowed")
            else:
                self._reply(200, b"upload ok: /uploads/" +
                            (m.group(1) if m else b"x"))

        def do_GET(self):
            if self.server.stored is not None:
                fn = self.path.rsplit("/", 1)[-1]
                for name, data in self.server.stored.items():
                    if name == fn:
                        self._reply(200, data)
                        return
            self._reply(404, b"not found")

        def _reply(self, code, body):
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return H


@pytest.fixture
def http_server():
    srv = _RecordingServer(("127.0.0.1", 0), _make_handler())
    srv.requests = []
    srv.stored = {}
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}/"
    yield srv
    srv.shutdown()
