"""Bounded socket listeners shared by the protocol decoys."""

import socket
import threading


class TCPDecoy(threading.Thread):
    protocol = "tcp"

    def __init__(self, host, port, profile, bus):
        super().__init__(daemon=True, name="mirageot-{}".format(self.protocol))
        self.host, self.port, self.profile, self.bus = host, port, profile, bus
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.bound = False
        self.server = None
        self.slots = threading.BoundedSemaphore(bus.cfg["max_clients_per_decoy"])

    def run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                self.server = server
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((self.host, self.port))
                server.listen(64)
                server.settimeout(0.5)
                self.bound = True
                with self.bus.lock:
                    self.bus.decoys_online.append({"protocol": self.protocol, "port": self.port})
                self.ready.set()
                while not self.stop_event.is_set():
                    try:
                        conn, addr = server.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not self.slots.acquire(blocking=False):
                        conn.close()
                        continue
                    conn.settimeout(5)
                    threading.Thread(target=self._serve, args=(conn, addr), daemon=True).start()
        except OSError as exc:
            print("[WARN] {}:{} unavailable: {}".format(self.protocol, self.port, exc))
        finally:
            self.ready.set()

    def _serve(self, conn, addr):
        try:
            with conn:
                self.bus.record(self.protocol, addr, "connect", "TCP session opened")
                self.handle(conn, addr)
        except (OSError, ValueError, UnicodeError) as exc:
            self.bus.record(self.protocol, addr, "invalid-frame", type(exc).__name__)
        finally:
            self.slots.release()

    def handle(self, conn, addr):
        raise NotImplementedError

    def stop(self):
        self.stop_event.set()
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass

    @staticmethod
    def recvn(conn, length):
        data = bytearray()
        while len(data) < length:
            try:
                chunk = conn.recv(length - len(data))
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            data.extend(chunk)
        return bytes(data)

    @staticmethod
    def readline(conn, limit=1024):
        data = bytearray()
        while len(data) < limit:
            chunk = conn.recv(1)
            if not chunk:
                break
            data.extend(chunk)
            if chunk == b"\n":
                return bytes(data)
        if len(data) >= limit:
            raise ValueError("line exceeds limit")
        return bytes(data)


class UDPDecoy(threading.Thread):
    protocol = "udp"

    def __init__(self, host, port, profile, bus):
        super().__init__(daemon=True, name="mirageot-{}".format(self.protocol))
        self.host, self.port, self.profile, self.bus = host, port, profile, bus
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.bound = False
        self.server = None

    def run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
                self.server = server
                server.bind((self.host, self.port))
                server.settimeout(0.5)
                self.bound = True
                with self.bus.lock:
                    self.bus.decoys_online.append({"protocol": self.protocol, "port": self.port})
                self.ready.set()
                while not self.stop_event.is_set():
                    try:
                        data, addr = server.recvfrom(2048)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    try:
                        self.handle(server, data, addr)
                    except (ValueError, IndexError, OSError):
                        self.bus.record(self.protocol, addr, "invalid-frame", "malformed UDP datagram")
        except OSError as exc:
            print("[WARN] {}:{} unavailable: {}".format(self.protocol, self.port, exc))
        finally:
            self.ready.set()

    def handle(self, server, data, addr):
        raise NotImplementedError

    def stop(self):
        self.stop_event.set()
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass
