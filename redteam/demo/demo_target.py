"""Vanguard demo target: a small, intentionally-vulnerable HTTP service.

Ships with the open repo so you can dogfood the red-team attacker locally without
touching a real service. It has three deliberate flaws matching the technique
playbook:

  * IDOR           GET /users/<id>        -> leaks PII with no auth check
  * JWT alg=none   POST /login            -> accepts an alg=none token
  * path traversal GET /files?name=<path> -> reads arbitrary files (../..)

DO NOT DEPLOY. Run it, attack it, then tear it down:

    python3 demo_target.py            # listens on :3000
    DEEPSEEK_API_KEY=... uv run python -c '...'   # point AgenticAttacker at it

Only stdlib. No dependencies.
"""

from __future__ import annotations

import base64
import json
import socketserver
import urllib.parse
from http.server import BaseHTTPRequestHandler

USERS = {
    "1": {"name": "alice", "role": "admin", "ssn": "111-22-3333"},
    "2": {"name": "bob", "role": "user", "ssn": "444-55-6666"},
}

_SECRET = "vanguard-demo-secret-do-not-use"


def _b64url_decode(part: str) -> dict:
    padded = part + "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, status: int = 200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            self._json(
                {
                    "ok": True,
                    "service": "vanguard-demo-target",
                    "routes": ["/users/<id>", "/login", "/files?name=<path>"],
                }
            )
        elif path.startswith("/users/"):
            uid = path.rsplit("/", 1)[-1]
            # VULN 1 (IDOR): no authz check on the object id.
            self._json(USERS.get(uid, {"error": "not found"}))
        elif path == "/files":
            name = qs.get("name", [""])[0]
            # VULN 3 (path traversal): name is used as a filesystem path verbatim.
            try:
                with open(name, encoding="utf-8") as f:
                    self._json({"content": f.read()})
            except OSError as exc:
                self._json({"error": str(exc)}, 404)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode() if length else "{}"
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/login":
            try:
                token = json.loads(raw).get("token", "")
                header, payload, _sig = (token.split(".") + ["", ""])[:3]
                hdr = _b64url_decode(header)
                # VULN 2 (JWT alg=none): algorithm confusion accepted verbatim.
                if hdr.get("alg") == "none":
                    pl = _b64url_decode(payload)
                    self._json({"logged_in": True, "role": pl.get("role"), "secret": _SECRET})
                else:
                    self._json({"error": "unsupported alg"}, 401)
            except Exception as exc:  # noqa: BLE001 - demo: report parse failure
                self._json({"error": str(exc)}, 400)
        else:
            self._json({"error": "not found"}, 404)

    def log_message(self, *args):  # noqa: ARG002 - silence request logs
        pass


if __name__ == "__main__":
    import sys

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", port), Handler) as srv:
        print(f"vanguard demo target listening on :{port} (DO NOT DEPLOY)")
        srv.serve_forever()
