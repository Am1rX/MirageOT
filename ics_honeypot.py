#!/usr/bin/env python3
"""
============================================================================
 PLCpot  -  Multi-protocol Industrial Honeypot (production-oriented)
============================================================================
A deceptive, self-contained ICS honeypot. It impersonates a real PLC so that any
attacker who touches it reveals themselves. There is NO real process behind it and
it NEVER connects outbound - it is a pure trap and sensor.

SERVICES (each configurable / toggleable):
  * Modbus/TCP   (port 502)  - full request handling, believable register bank
  * S7comm       (port 102)  - Siemens TPKT/COTP handshake + request logging
  * Fake Web HMI (port 8080) - vendor-style login page; logs credential attempts

FEATURES:
  * Selectable device profile (Siemens / Schneider / Allen-Bradley)
  * Structured JSON-lines logging + console + optional CEF syslog to a SIEM
  * Per-source session tracking and summary stats
  * Zero external dependencies (Python stdlib only)

WHY IT WORKS: OT networks are quiet and predictable, so a device nobody should talk
to yields near-zero false positives - almost every hit is hostile. Deploy it in a
monitored segment (e.g. the industrial DMZ) as an early-warning tripwire.

  This is the production sibling of the teaching lab `labs/lab07_honeypot.py`.
"""
import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
from collections import defaultdict

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if os.name == "nt":
    os.system("")


class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; CY = "\033[36m"
    GR = "\033[90m"; BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"
    YEL_BG = "\033[43m\033[30m"


# ---------------------------------------------------------------------------
# Device profiles (identity the honeypot advertises)
# ---------------------------------------------------------------------------
PROFILES = {
    "siemens_s7_1200": {
        "vendor": "Siemens", "product": "SIMATIC S7-1200 CPU 1214C",
        "revision": "V4.2.3", "server_header": "Siemens, SIMATIC, CP 343",
        "modbus_ir": [4720, 6130, 890, 320, 4150], "web": True, "s7": True,
    },
    "schneider_m340": {
        "vendor": "Schneider Electric", "product": "Modicon M340 BMXP342020",
        "revision": "2.60", "server_header": "Schneider-WEB/V2.1",
        "modbus_ir": [5010, 4980, 1200, 410, 3800], "web": True, "s7": False,
    },
    "allen_bradley": {
        "vendor": "Rockwell/Allen-Bradley", "product": "MicroLogix 1400",
        "revision": "21.003", "server_header": "A-B WWW/1.0",
        "modbus_ir": [4300, 5600, 760, 290, 4020], "web": True, "s7": False,
    },
}


# ===========================================================================
# Structured logger
# ===========================================================================
class HoneyLog:
    def __init__(self, path, syslog=None):
        self.fh = open(path, "a", encoding="utf-8")
        self.lock = threading.Lock()
        self.stats = defaultdict(int)
        self.sources = set()
        self.syslog = None
        if syslog:
            host, _, port = syslog.partition(":")
            self.syslog = (host, int(port or 514))
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def event(self, service, src, action, detail, severity="MEDIUM"):
        ip = src[0] if isinstance(src, tuple) else src
        rec = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "service": service,
               "src_ip": ip, "src_port": src[1] if isinstance(src, tuple) else None,
               "action": action, "detail": detail, "severity": severity}
        with self.lock:
            self.stats[action] += 1
            self.sources.add(ip)
            self.fh.write(json.dumps(rec, ensure_ascii=False) + "\n"); self.fh.flush()
        color = C.R if severity in ("HIGH", "CRITICAL") else C.Y if action != "connect" else C.CY
        icon = {"connect": "[*]", "read": "[r]", "write": "[!]",
                "login-attempt": "[K]", "probe": "[?]"}.get(action, "[.]")
        print(f"{color}{icon} {service:<7}{C.RESET} {C.BOLD}{ip}{C.RESET} "
              f"{C.GR}{action}{C.RESET} {detail}")
        if self.syslog:
            self._cef(rec)

    def _cef(self, r):
        sev = {"LOW": 3, "MEDIUM": 6, "HIGH": 8, "CRITICAL": 10}.get(r["severity"], 5)
        cef = (f"CEF:0|ICS-Academy|PLCpot|1.0|{r['action']}|{r['service']} {r['detail']}|{sev}|"
               f"src={r['src_ip']} app={r['service']}")
        msg = f"<{16*8+sev}>{time.strftime('%b %d %H:%M:%S')} plcpot {cef}"
        try:
            self.sock.sendto(msg.encode(), self.syslog)
        except Exception:
            pass

    def summary(self):
        with self.lock:
            print(f"\n{C.BOLD}== PLCpot summary =={C.RESET}")
            print(f"   unique attacker IPs: {len(self.sources)}")
            for k, v in sorted(self.stats.items(), key=lambda x: -x[1]):
                print(f"   {k:<16} {v}")


# ===========================================================================
# Modbus service (full request handling on a fake register bank)
# ===========================================================================
WRITE_FUNCS = {5, 6, 15, 16}
FUNC_NAMES = {1: "read-coils", 2: "read-discrete", 3: "read-holding", 4: "read-input",
              5: "write-coil", 6: "write-register", 15: "write-coils", 16: "write-registers"}


class ModbusHoneypot(threading.Thread):
    def __init__(self, host, port, profile, log):
        super().__init__(daemon=True)
        self.host, self.port, self.profile, self.log = host, port, profile, log
        self.coils = [False] * 128
        self.di = [False] * 128
        self.ir = [0] * 128
        self.hr = [0] * 128
        for i, v in enumerate(profile["modbus_ir"]):
            self.ir[i] = v
        self.hr[:5] = [6000, 5500, 7000, 1000, 8500]
        self._stop = threading.Event()

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port)); srv.listen(20); srv.settimeout(1.0)
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
        srv.close()

    def _handle(self, conn, addr):
        self.log.event("modbus", addr, "connect", "TCP session opened")
        try:
            while True:
                hdr = self._recvn(conn, 7)
                if not hdr:
                    break
                tid, proto, length, unit = struct.unpack(">HHHB", hdr)
                pdu = self._recvn(conn, length - 1)
                if not pdu:
                    break
                resp = self._process(addr, unit, pdu)
                conn.sendall(struct.pack(">HHHB", tid, 0, len(resp) + 1, unit) + resp)
        except OSError:
            pass
        finally:
            conn.close()

    def _process(self, addr, unit, pdu):
        func = pdu[0]
        try:
            if func in (1, 2, 3, 4):
                a, cnt = struct.unpack(">HH", pdu[1:5])
                self.log.event("modbus", addr, "read",
                               f"{FUNC_NAMES[func]} @{a} x{cnt} (unit {unit})", "LOW")
                if func in (1, 2):
                    src = self.coils if func == 1 else self.di
                    bits = src[a:a + cnt]; bc = (cnt + 7) // 8
                    data = bytearray(bc)
                    for i, b in enumerate(bits):
                        if b:
                            data[i // 8] |= 1 << (i % 8)
                    return struct.pack(">BB", func, bc) + bytes(data)
                src = self.hr if func == 3 else self.ir
                regs = src[a:a + cnt]
                return struct.pack(">BB", func, cnt * 2) + b"".join(struct.pack(">H", r) for r in regs)

            if func in WRITE_FUNCS:
                if func == 5:
                    a, raw = struct.unpack(">HH", pdu[1:5]); val = raw == 0xFF00
                    self.coils[a] = val
                    self.log.event("modbus", addr, "write",
                                   f"write-coil @{a} = {int(val)}  <<ATTACKER TRIED TO ACTUATE>>", "HIGH")
                    return pdu[:5]
                if func == 6:
                    a, val = struct.unpack(">HH", pdu[1:5]); self.hr[a] = val
                    self.log.event("modbus", addr, "write",
                                   f"write-register @{a} = {val}  <<SETPOINT TAMPER ATTEMPT>>", "HIGH")
                    return pdu[:5]
                if func in (15, 16):
                    a, cnt = struct.unpack(">HH", pdu[1:5])
                    self.log.event("modbus", addr, "write",
                                   f"{FUNC_NAMES[func]} @{a} x{cnt}  <<BULK WRITE ATTACK>>", "HIGH")
                    return struct.pack(">BHH", func, a, cnt)
            # unsupported
            self.log.event("modbus", addr, "probe", f"unsupported function 0x{func:02x}", "MEDIUM")
            return struct.pack(">BB", func | 0x80, 0x01)
        except (struct.error, IndexError):
            return struct.pack(">BB", func | 0x80, 0x02)

    @staticmethod
    def _recvn(conn, n):
        buf = b""
        while len(buf) < n:
            try:
                c = conn.recv(n - len(buf))
            except OSError:
                return None
            if not c:
                return None
            buf += c
        return buf

    def stop(self):
        self._stop.set()


# ===========================================================================
# S7comm service (Siemens) - TPKT/COTP handshake + request logging
# ===========================================================================
class S7Honeypot(threading.Thread):
    def __init__(self, host, port, profile, log):
        super().__init__(daemon=True)
        self.host, self.port, self.profile, self.log = host, port, profile, log
        self._stop = threading.Event()

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.host, self.port))
        except OSError as e:
            print(f"{C.Y}[!] S7 port {self.port} unavailable ({e}); skipping.{C.RESET}")
            return
        srv.listen(20); srv.settimeout(1.0)
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
        srv.close()

    def _handle(self, conn, addr):
        self.log.event("s7comm", addr, "connect", "TPKT/COTP session opened")
        try:
            while True:
                data = conn.recv(512)
                if not data:
                    break
                # TPKT header: 03 00 LL LL, then COTP
                if len(data) >= 6 and data[0] == 0x03:
                    cotp_type = data[5]
                    if cotp_type == 0xE0:  # COTP Connection Request -> reply Connection Confirm
                        cc = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xD0, 0x00, 0x01,
                                    0x00, 0x02, 0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02,
                                    0x01, 0x02, 0xC2, 0x02, 0x01, 0x02])
                        conn.sendall(cc)
                        self.log.event("s7comm", addr, "probe",
                                       "COTP connection request (Siemens PLC discovery)", "MEDIUM")
                    else:
                        # S7 job/setup - log and send a benign S7 ACK-ish echo
                        self.log.event("s7comm", addr, "probe",
                                       f"S7 PDU type 0x{cotp_type:02x} (setup/read attempt)", "HIGH")
                        conn.sendall(data[:4] + b"\x02\xf0\x80")
                else:
                    self.log.event("s7comm", addr, "probe", "non-TPKT bytes", "MEDIUM")
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self):
        self._stop.set()


# ===========================================================================
# Fake Web HMI service - logs credential attempts
# ===========================================================================
class WebHoneypot(threading.Thread):
    def __init__(self, host, port, profile, log):
        super().__init__(daemon=True)
        self.host, self.port, self.profile, self.log = host, port, profile, log
        self._stop = threading.Event()

    PAGE = ("<!doctype html><html><head><title>{product} - Web Server</title></head>"
            "<body style='font-family:Arial;background:#222;color:#eee'>"
            "<h2>{vendor} {product}</h2><p>Firmware {revision}</p>"
            "<form method='POST' action='/login'>User <input name='user'> "
            "Password <input type='password' name='pass'> "
            "<button>Sign in</button></form></body></html>")

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.host, self.port))
        except OSError as e:
            print(f"{C.Y}[!] Web port {self.port} unavailable ({e}); skipping.{C.RESET}")
            return
        srv.listen(20); srv.settimeout(1.0)
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
        srv.close()

    def _handle(self, conn, addr):
        try:
            req = conn.recv(4096).decode("latin1")
            line = req.split("\r\n", 1)[0]
            if req.startswith("POST /login"):
                body = req.split("\r\n\r\n", 1)[-1]
                self.log.event("web-hmi", addr, "login-attempt",
                               f"credentials '{body[:120]}'  <<BRUTE FORCE / DEFAULT CREDS>>", "HIGH")
                page = "<html><body>Invalid credentials</body></html>"
            else:
                self.log.event("web-hmi", addr, "read", f"HTTP {line}", "LOW")
                page = self.PAGE.format(**self.profile)
            hdr = (f"HTTP/1.1 200 OK\r\nServer: {self.profile['server_header']}\r\n"
                   f"Content-Type: text/html\r\nContent-Length: {len(page)}\r\n"
                   f"Connection: close\r\n\r\n")
            conn.sendall((hdr + page).encode("latin1"))
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self):
        self._stop.set()


# ===========================================================================
# main
# ===========================================================================
def main():
    ap = argparse.ArgumentParser(description="PLCpot - multi-protocol ICS honeypot")
    ap.add_argument("--profile", default="siemens_s7_1200", choices=list(PROFILES))
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--modbus-port", type=int, default=502)
    ap.add_argument("--s7-port", type=int, default=102)
    ap.add_argument("--web-port", type=int, default=8080)
    ap.add_argument("--no-s7", action="store_true")
    ap.add_argument("--no-web", action="store_true")
    ap.add_argument("--log", default="honeypot_events.jsonl")
    ap.add_argument("--syslog", help="forward CEF alerts to HOST:PORT")
    ap.add_argument("--config", help="JSON config file (overrides CLI)")
    args = ap.parse_args()

    if args.config:
        with open(args.config, encoding="utf-8") as f:
            cfg = json.load(f)
        for k, v in cfg.items():
            setattr(args, k.replace("-", "_"), v)

    profile = PROFILES[args.profile]
    log = HoneyLog(args.log, args.syslog)

    print(f"{C.BOLD}{C.CY}== PLCpot :: multi-protocol ICS honeypot =={C.RESET}")
    print(f"{C.GR}   posing as: {profile['vendor']} {profile['product']} (fw {profile['revision']})")
    print(f"   log: {args.log}{'  syslog: ' + args.syslog if args.syslog else ''}{C.RESET}\n")

    services = [ModbusHoneypot(args.host, args.modbus_port, profile, log)]
    print(f"{C.G}[+] Modbus/TCP  on {args.host}:{args.modbus_port}{C.RESET}")
    if profile["s7"] and not args.no_s7:
        services.append(S7Honeypot(args.host, args.s7_port, profile, log))
        print(f"{C.G}[+] S7comm      on {args.host}:{args.s7_port}{C.RESET}")
    if profile["web"] and not args.no_web:
        services.append(WebHoneypot(args.host, args.web_port, profile, log))
        print(f"{C.G}[+] Web HMI     on {args.host}:{args.web_port}{C.RESET}")

    for s in services:
        s.start()
    print(f"\n{C.YEL_BG} TRAP ARMED {C.RESET}  waiting for attackers... (Ctrl+C to stop)\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for s in services:
            s.stop()
        log.summary()


if __name__ == "__main__":
    main()
