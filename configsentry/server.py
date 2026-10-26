"""Local web server for the ConfigSentry web app.

Uses only the Python standard library. It listens on 127.0.0.1 only and
rejects requests whose Host header is not localhost, so other machines and
web pages (DNS rebinding) cannot reach it. Configurations are processed in
memory and never written to disk.
"""

from __future__ import annotations

import json
import mimetypes
import os
import socket
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .engine import PLATFORMS, load_rules, run_audit
from .masking import mask_line
from .parsers import detect_platform, read_upload
from .report import to_html, to_json

WEB_DIR = Path(__file__).parent / "web"
MAX_UPLOAD = 25 * 1024 * 1024
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]"}


def _result_payload(result) -> dict:
    data = result.to_dict()
    for r in data["results"]:
        r["evidence_masked"] = [mask_line(e) for e in r["evidence"]]
    data["platform_key"] = result.platform
    return data


def _meta() -> dict:
    return {
        "version": __version__,
        "platforms": [
            {"key": k, "name": v["name"], "kind": v["kind"], "command": v["command"],
             "rules": len(load_rules(k))}
            for k, v in PLATFORMS.items()
        ],
    }


def _rules() -> dict:
    out = {}
    for key, info in PLATFORMS.items():
        out[key] = {
            "name": info["name"],
            "kind": info["kind"],
            "rules": [
                {k: r.get(k) for k in ("id", "title", "severity", "category", "description", "references")}
                for r in load_rules(key)
            ],
        }
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "ConfigSentry"
    sys_version = ""

    # -- helpers --------------------------------------------------------- #
    def log_message(self, fmt, *args):  # keep the console quiet
        pass

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].lower()
        return host in ALLOWED_HOSTS

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, code: int = 200) -> None:
        self._send(code, json.dumps(data).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, message: str, code: int = 400) -> None:
        self._json({"status": "error", "message": message}, code)

    def _body(self) -> bytes | None:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD:
            self._error(f"The file is too large. The limit is {MAX_UPLOAD // (1024 * 1024)} MB.", 413)
            return None
        return self.rfile.read(length) if length else b""

    # -- routes ---------------------------------------------------------- #
    def do_GET(self):
        if not self._host_ok():
            return self._error("Forbidden host.", 403)
        path = urlparse(self.path).path
        if path == "/api/meta":
            return self._json(_meta())
        if path == "/api/rules":
            return self._json(_rules())
        if path in ("/", "/index.html", "/rules", "/about"):
            path = "/index.html"
        target = (WEB_DIR / path.lstrip("/")).resolve()
        if WEB_DIR.resolve() not in target.parents or not target.is_file():
            return self._error("Not found.", 404)
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self._send(200, target.read_bytes(), ctype)

    def do_POST(self):
        if not self._host_ok():
            return self._error("Forbidden host.", 403)
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        body = self._body()
        if body is None:
            return
        name = q.get("name") or "pasted configuration"
        try:
            text = read_upload(name, body)
        except Exception as exc:  # noqa: BLE001
            return self._error(f"The file could not be read: {exc}")
        if not text.strip():
            return self._error("The configuration is empty.")

        requested = q.get("platform", "auto")
        detected = detect_platform(text)
        if requested == "auto":
            if not detected:
                return self._json({"status": "choose", "message":
                                   "The platform could not be detected. Choose it and run the audit again."})
            platform = detected
        elif requested in PLATFORMS:
            platform = requested
            if detected and detected != requested and q.get("force") != "1":
                return self._json({"status": "mismatch", "detected": detected, "selected": requested})
        else:
            return self._error("Unknown platform.")

        try:
            result = run_audit(text, platform, source=name, mask=False)
        except ValueError as exc:
            return self._error(str(exc))

        if url.path == "/api/audit":
            return self._json({"status": "ok", "detected": detected, "result": _result_payload(result)})

        if url.path == "/api/report":
            mask = q.get("mask", "1") != "0"
            if mask:
                for r in result.results:
                    r.evidence = [mask_line(e) for e in r.evidence]
            host = (result.hostname or "device").replace(" ", "_")
            if q.get("format") == "json":
                data, ctype, ext = to_json(result).encode("utf-8"), "application/json", "json"
            else:
                data, ctype, ext = to_html(result, masked=mask).encode("utf-8"), "text/html; charset=utf-8", "html"
            return self._send(200, data, ctype,
                              {"Content-Disposition": f'attachment; filename="configsentry_{host}.{ext}"'})

        return self._error("Not found.", 404)


def _free_port(start: int = 8501, tries: int = 20) -> int:
    for port in range(start, start + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise OSError("No free port found between 8501 and 8520.")


def make_server(port: int = 0) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(open_browser: bool = True, port: int | None = None) -> None:
    port = port or _free_port()
    httpd = make_server(port)
    url = f"http://localhost:{port}"
    print(f"ConfigSentry {__version__} is running at {url}")
    print("Close this window or press Ctrl+C to stop.")
    headless = sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if open_browser and not headless:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    elif headless:
        print("No desktop found. Open the address above in a browser on this machine, or from your")
        print(f"PC through an SSH tunnel:  ssh -L {port}:localhost:{port} user@this-server")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
