"""Read-only console and JSON API."""

import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .dashboard import DASHBOARD_HTML


class Console:
    def __init__(self, bus, host, port, token=None):
        self.bus, self.host, self.port, self.token = bus, host, port, token
        self.server = None
        self.thread = None

    def start(self):
        bus, token = self.bus, self.token

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def send_body(self, status, body, content_type):
                if isinstance(body, str):
                    body = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", content_type + "; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_GET(self):
                if self.path in ("/", "/index.html"):
                    return self.send_body(200, DASHBOARD_HTML, "text/html")
                if self.path not in ("/api/stats", "/api/intel"):
                    return self.send_body(404, "not found", "text/plain")
                if token and not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token):
                    return self.send_body(401, json.dumps({"error": "authorization required"}), "application/json")
                data = bus.snapshot() if self.path == "/api/stats" else bus.write_intel()
                return self.send_body(200, json.dumps(data, ensure_ascii=False), "application/json")

        class BoundedHTTPServer(ThreadingHTTPServer):
            daemon_threads = True
            request_queue_size = 32

            def __init__(self, *args, **kwargs):
                self.slots = threading.BoundedSemaphore(32)
                super().__init__(*args, **kwargs)

            def get_request(self):
                client, address = super().get_request()
                client.settimeout(5)
                return client, address

            def process_request(self, request, client_address):
                if not self.slots.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, client_address)
                except BaseException:
                    self.slots.release()
                    raise

            def process_request_thread(self, request, client_address):
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self.slots.release()

        self.server = BoundedHTTPServer((self.host, self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True, name="mirageot-console")
        self.thread.start()
        return self

    def close(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=2)
