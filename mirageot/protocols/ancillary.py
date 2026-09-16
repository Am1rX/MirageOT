"""Bounded ancillary service decoys."""

import html
from urllib.parse import parse_qs, urlsplit

from .base import TCPDecoy


class FTPDecoy(TCPDecoy):
    protocol = "ftp"

    def handle(self, conn, addr):
        conn.sendall("220 {} PLC FTP ready\r\n".format(self.profile["vendor"]).encode())
        username = ""
        for _ in range(20):
            line = self.readline(conn, 512)
            if not line:
                return
            command, _, argument = line.decode("latin1").strip().partition(" ")
            command = command.upper()
            if command == "USER":
                username = argument[:64]
                conn.sendall(b"331 Password required\r\n")
            elif command == "PASS":
                self.bus.record(self.protocol, addr, "login-attempt", "FTP user={!r} password={!r}".format(username, argument[:64]))
                conn.sendall(b"530 Login incorrect\r\n")
            elif command == "QUIT":
                conn.sendall(b"221 Goodbye\r\n")
                return
            else:
                conn.sendall(b"502 Command not implemented\r\n")


class TelnetDecoy(TCPDecoy):
    protocol = "telnet"

    def handle(self, conn, addr):
        conn.sendall("\r\n{} maintenance console\r\nlogin: ".format(self.profile["product"]).encode())
        username = self.readline(conn, 128).decode("latin1", "replace").strip()
        if not username:
            return
        conn.sendall(b"Password: ")
        password = self.readline(conn, 128).decode("latin1", "replace").strip()
        self.bus.record(self.protocol, addr, "login-attempt", "Telnet user={!r} password={!r}".format(username[:64], password[:64]))
        conn.sendall(b"\r\nLogin incorrect\r\n")


class WebDecoy(TCPDecoy):
    protocol = "web-hmi"

    def handle(self, conn, addr):
        line = self.readline(conn, 2048).decode("latin1", "replace").strip()
        parts = line.split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/"):
            raise ValueError("invalid HTTP request line")
        method, target, _ = parts
        headers = {}
        for _ in range(50):
            raw = self.readline(conn, 2048)
            if raw in (b"\r\n", b"\n", b""):
                break
            name, sep, value = raw.decode("latin1", "replace").partition(":")
            if not sep:
                raise ValueError("invalid HTTP header")
            headers[name.lower()] = value.strip()
        else:
            raise ValueError("too many HTTP headers")
        path = urlsplit(target).path
        if path.startswith("/token/"):
            self.bus.record(self.protocol, addr, "token-trip", "honeytoken URL requested")
            body = "<html><body>OK</body></html>"
        elif method == "POST" and path == "/login":
            length = int(headers.get("content-length", "0"))
            if not 0 <= length <= 4096:
                raise ValueError("invalid HTTP body length")
            payload = self.recvn(conn, length) if length else b""
            if payload is None:
                return
            fields = parse_qs(payload.decode("utf-8", "replace"))
            username = fields.get("user", [""])[0][:64]
            password = fields.get("pass", [""])[0][:64]
            self.bus.record(self.protocol, addr, "login-attempt", "Web user={!r} password={!r}".format(username, password))
            body = "<html><body>Invalid credentials</body></html>"
        else:
            self.bus.record(self.protocol, addr, "read", "HTTP {} {}".format(method[:8], path[:120]))
            vendor = html.escape(self.profile["vendor"])
            product = html.escape(self.profile["product"])
            revision = html.escape(self.profile["rev"])
            body = ("<!doctype html><title>{}</title><body><h2>{} {}</h2><p>Firmware {}</p>"
                    "<form method=POST action=/login>User <input name=user> "
                    "Password <input type=password name=pass><button>Sign in</button></form></body>") .format(
                        product, vendor, product, revision)
        content = body.encode("utf-8")
        response = ("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                    "Content-Length: {}\r\nConnection: close\r\n\r\n".format(len(content))).encode("ascii")
        conn.sendall(response + content)
