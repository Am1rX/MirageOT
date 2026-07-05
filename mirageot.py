#!/usr/bin/env python3
"""
============================================================================
 MirageOT  -  Open-Source ICS/OT Deception Platform
============================================================================
A multi-protocol industrial deception grid that stands next to commercial
platforms like FortiDeceptor, TrapX and Attivo - but open, hackable and free.

WHAT IT DOES
  * Deploys many protocol DECOYS at once (Modbus, S7comm, DNP3, IEC-104,
    EtherNet/IP, BACnet, SNMP, FTP, Telnet, Web-HMI) that impersonate real PLCs.
  * Correlates every interaction into per-attacker SESSIONS with a rising
    THREAT SCORE (recon -> interaction -> manipulation).
  * Tags activity with MITRE ATT&CK for ICS techniques.
  * Ships a live WEB CONSOLE (dashboard) for the SOC - great for demos & Medium.
  * Exports THREAT INTEL (attacker IOCs) and an auto-generated firewall BLOCKLIST.
  * Streams alerts to a SIEM (CEF/syslog) and to a WEBHOOK (Slack/Teams/SOAR).

Everything is Python stdlib only. See README.md for deployment and safety.

  Run:   python mirageot.py                      (uses built-in defaults)
         python mirageot.py --config config.json (production)
         python mirageot.py --demo               (safe high ports for a laptop)
  Then:  open the web console printed at startup.
"""
import argparse
import ipaddress
import json
import os
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if os.name == "nt":
    os.system("")

VERSION = "1.0"


class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; CY = "\033[36m"; M = "\033[35m"
    GR = "\033[90m"; BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"
    YEL_BG = "\033[43m\033[30m"; RED_BG = "\033[41m\033[97m"


# ---------------------------------------------------------------------------
# Device profiles (identity the decoys advertise)
# ---------------------------------------------------------------------------
PROFILES = {
    "siemens_s7_1200": {"vendor": "Siemens", "product": "SIMATIC S7-1200 CPU 1214C",
        "rev": "V4.2.3", "server": "Siemens, SIMATIC, CP 343", "sys": "Siemens SIMATIC S7-1200"},
    "schneider_m340": {"vendor": "Schneider Electric", "product": "Modicon M340 BMXP342020",
        "rev": "2.60", "server": "Schneider-WEB/V2.1", "sys": "Schneider Modicon M340"},
    "allen_bradley": {"vendor": "Rockwell/Allen-Bradley", "product": "MicroLogix 1400",
        "rev": "21.003", "server": "A-B WWW/1.0", "sys": "Allen-Bradley MicroLogix 1400"},
    "ge_rx3i": {"vendor": "GE", "product": "PACSystems RX3i", "rev": "9.75",
        "server": "GE-HTTP/1.0", "sys": "GE PACSystems RX3i"},
}

# MITRE ATT&CK for ICS technique map (action -> (id, name))
MITRE = {
    "connect":        ("T0846", "Remote System Discovery"),
    "read":           ("T0801", "Monitor Process State"),
    "point-id":       ("T0861", "Point & Tag Identification"),
    "discover":       ("T0846", "Remote System Discovery"),
    "sysinfo":        ("T0888", "Remote System Information Discovery"),
    "write":          ("T0855", "Unauthorized Command Message"),
    "manipulate":     ("T0831", "Manipulation of Control"),
    "modify-param":   ("T0836", "Modify Parameter"),
    "loss-safety":    ("T0880", "Loss of Safety"),
    "login-attempt":  ("T0812", "Default Credentials"),
    "brute":          ("T0859", "Valid Accounts"),
    "token-trip":     ("T0865", "Spearphishing Attachment"),
}

# action -> base severity + threat-score weight
ACTION_META = {
    "connect": ("LOW", 1), "read": ("LOW", 1), "discover": ("LOW", 2),
    "sysinfo": ("MEDIUM", 3), "point-id": ("MEDIUM", 3),
    "write": ("HIGH", 10), "manipulate": ("HIGH", 12), "modify-param": ("HIGH", 12),
    "loss-safety": ("CRITICAL", 20), "login-attempt": ("HIGH", 8),
    "brute": ("HIGH", 9), "token-trip": ("CRITICAL", 25),
}


# ===========================================================================
# Attacker session + central event bus
# ===========================================================================
class Session:
    def __init__(self, ip):
        self.ip = ip
        self.first = time.time()
        self.last = self.first
        self.events = 0
        self.score = 0
        self.techniques = {}          # id -> name
        self.decoys = set()
        self.actions = defaultdict(int)

    def stage(self):
        if self.score >= 20: return "MANIPULATION"
        if self.score >= 8:  return "INTERACTION"
        return "RECON"

    def as_dict(self):
        return {"ip": self.ip, "first_seen": _iso(self.first), "last_seen": _iso(self.last),
                "events": self.events, "score": self.score, "stage": self.stage(),
                "techniques": [{"id": k, "name": v} for k, v in self.techniques.items()],
                "decoys": sorted(self.decoys), "actions": dict(self.actions)}


class EventBus:
    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.RLock()
        self.log_fh = open(cfg.get("log", "mirageot_events.jsonl"), "a", encoding="utf-8")
        self.sessions = {}
        self.recent = deque(maxlen=400)
        self.stats = defaultdict(int)
        self.by_protocol = defaultdict(int)
        self.by_severity = defaultdict(int)
        self.techniques = {}
        self.started = time.time()
        self.decoys_online = []
        # sinks
        self.syslog = _parse_hostport(cfg.get("syslog"))
        if self.syslog:
            self.usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.webhook = cfg.get("webhook")
        self.blocklist_path = cfg.get("blocklist", "blocklist.txt")
        self.intel_path = cfg.get("intel", "threat_intel.json")
        self.block_threshold = cfg.get("block_threshold", 10)
        # --- OT-safe response policy ---
        # In OT, availability & safety come first, so auto-blocking a production IP can
        # itself cause an outage. Default is DETECT-ONLY: raise the alert, let a human
        # decide. Set response_mode="blocklist" only for untrusted (IT/external) sources,
        # and always list critical assets/scanners in never_block so they are NEVER dropped.
        self.response_mode = cfg.get("response_mode", "alert-only")  # alert-only | blocklist
        self.never_block = []
        for entry in cfg.get("never_block", []):
            try:
                self.never_block.append(ipaddress.ip_network(str(entry), strict=False))
            except ValueError:
                print(f"{C.Y}[!] never_block: bad entry '{entry}' ignored{C.RESET}")
        self._recommended = set()

    def record(self, protocol, src, action, detail):
        ip = src[0] if isinstance(src, tuple) else str(src).split(":")[0]
        severity, weight = ACTION_META.get(action, ("MEDIUM", 4))
        tech = MITRE.get(action)
        ts = time.time()
        rec = {"time": _iso(ts), "protocol": protocol, "src_ip": ip,
               "action": action, "detail": detail, "severity": severity,
               "technique": {"id": tech[0], "name": tech[1]} if tech else None}
        with self.lock:
            s = self.sessions.get(ip) or self.sessions.setdefault(ip, Session(ip))
            s.last = ts; s.events += 1; s.score += weight; s.decoys.add(protocol)
            s.actions[action] += 1
            if tech:
                s.techniques[tech[0]] = tech[1]; self.techniques[tech[0]] = tech[1]
            rec["session_score"] = s.score
            rec["session_stage"] = s.stage()
            self.stats[action] += 1
            self.by_protocol[protocol] += 1
            self.by_severity[severity] += 1
            self.recent.appendleft(rec)
            self.log_fh.write(json.dumps(rec, ensure_ascii=False) + "\n"); self.log_fh.flush()
            # --- decide response (OT-safe) ---
            decision = None
            if s.score >= self.block_threshold and ip not in self._recommended and ip not in self._blocked():
                protected = self._is_protected(ip)
                if self.response_mode == "blocklist" and not protected:
                    decision = ("block", protected)
                else:
                    decision = ("recommend", protected)
                self._recommended.add(ip)
            self._console(rec, s)
        if self.syslog: self._cef(rec)
        if self.webhook and severity in ("HIGH", "CRITICAL"): self._post_webhook(rec, s)
        if decision and decision[0] == "block":
            self._add_block(ip, s)
        elif decision and decision[0] == "recommend":
            self._recommend_block(ip, s, decision[1])

    # ---- outputs ----
    def _console(self, r, s):
        col = {"LOW": C.CY, "MEDIUM": C.Y, "HIGH": C.R, "CRITICAL": C.RED_BG}[r["severity"]]
        icon = {"connect": "*", "read": "r", "write": "!", "manipulate": "!!",
                "login-attempt": "K", "discover": "?", "token-trip": "TOKEN"}.get(r["action"], ".")
        t = r["technique"]["id"] if r["technique"] else "-"
        print(f"{col}[{icon}] {r['protocol']:<8}{C.RESET} {C.BOLD}{r['src_ip']:<15}{C.RESET} "
              f"{C.GR}{r['action']:<13}{C.RESET} {r['detail']}  "
              f"{C.DIM}[{t} | score {s.score} {s.stage()}]{C.RESET}")

    def _cef(self, r):
        sev = {"LOW": 3, "MEDIUM": 6, "HIGH": 8, "CRITICAL": 10}[r["severity"]]
        t = r["technique"]["id"] if r["technique"] else ""
        cef = (f"CEF:0|ICS-Academy|MirageOT|{VERSION}|{r['action']}|{r['protocol']}: {r['detail']}|{sev}|"
               f"src={r['src_ip']} app={r['protocol']} cs1Label=MitreID cs1={t} "
               f"cn1Label=SessionScore cn1={r.get('session_score',0)}")
        msg = f"<{16*8+sev}>{datetime.now().strftime('%b %d %H:%M:%S')} mirageot {cef}"
        try: self.usock.sendto(msg.encode(), self.syslog)
        except Exception: pass

    def _post_webhook(self, r, s):
        import urllib.request
        payload = {"text": f"[MirageOT] {r['severity']} - {r['protocol']} {r['action']} "
                           f"from {r['src_ip']} (score {s.score}, {s.stage()}): {r['detail']}"}
        try:
            req = urllib.request.Request(self.webhook, data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=3).read()
        except Exception:
            pass

    def _blocked(self):
        if not os.path.exists(self.blocklist_path):
            return set()
        with open(self.blocklist_path, encoding="utf-8") as f:
            return {ln.split("#")[0].strip() for ln in f if ln.strip() and not ln.startswith("#")}

    def _is_protected(self, ip):
        """True if the source must NEVER be auto-blocked (critical assets, scanners)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # unparseable -> err on the side of NOT blocking
        return any(addr in net for net in self.never_block)

    def _add_block(self, ip, s):
        with open(self.blocklist_path, "a", encoding="utf-8") as f:
            f.write(f"{ip}   # score={s.score} stage={s.stage()} at {_iso(time.time())}\n")
        print(f"{C.RED_BG} AUTO-RESPONSE {C.RESET} {C.R}added {ip} to {self.blocklist_path} "
              f"(threat score {s.score}) - untrusted source, blocklist mode{C.RESET}")
        self._write_intel()

    def _recommend_block(self, ip, s, protected):
        """OT-safe path: flag for human review instead of dropping traffic."""
        why = "on never_block allowlist" if protected else "response_mode=alert-only (OT-safe default)"
        print(f"{C.YEL_BG} REVIEW {C.RESET} {C.Y}{ip} reached threat score {s.score} ({s.stage()}) "
              f"- NOT auto-blocked ({why}). Investigate; block manually only if it is not a "
              f"production/safety asset.{C.RESET}")
        self._write_intel()

    def _write_intel(self):
        with self.lock:
            data = {"generated": _iso(time.time()), "sensor": "MirageOT",
                    "indicators": [s.as_dict() for s in self.sessions.values() if s.score >= 5]}
        try:
            with open(self.intel_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def snapshot(self):
        with self.lock:
            top = sorted(self.sessions.values(), key=lambda x: -x.score)[:12]
            return {
                "version": VERSION,
                "uptime": int(time.time() - self.started),
                "decoys_online": self.decoys_online,
                "totals": {"events": sum(self.stats.values()),
                           "attackers": len(self.sessions),
                           "manipulation": sum(1 for s in self.sessions.values() if s.stage() == "MANIPULATION"),
                           "blocked": len(self._blocked())},
                "by_protocol": dict(self.by_protocol),
                "by_severity": dict(self.by_severity),
                "techniques": [{"id": k, "name": v} for k, v in self.techniques.items()],
                "top_attackers": [s.as_dict() for s in top],
                "recent": list(self.recent)[:60],
            }


def _iso(ts): return datetime.fromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%S")
def _parse_hostport(v):
    if not v: return None
    h, _, p = v.partition(":"); return (h, int(p or 514))


# ===========================================================================
# Decoy base + protocol implementations
# ===========================================================================
class TCPDecoy(threading.Thread):
    protocol = "tcp"
    def __init__(self, host, port, profile, bus):
        super().__init__(daemon=True)
        self.host, self.port, self.profile, self.bus = host, port, profile, bus
        self._stop = threading.Event()
    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.host, self.port))
        except OSError as e:
            print(f"{C.Y}[!] {self.protocol} port {self.port} unavailable ({e}); skipped.{C.RESET}")
            return
        srv.listen(30); srv.settimeout(1.0)
        self.bus.decoys_online.append({"protocol": self.protocol, "port": self.port})
        while not self._stop.is_set():
            try: conn, addr = srv.accept()
            except socket.timeout: continue
            except OSError: break
            threading.Thread(target=self._safe, args=(conn, addr), daemon=True).start()
        srv.close()
    def _safe(self, conn, addr):
        self.bus.record(self.protocol, addr, "connect", "TCP session opened")
        try: self.handle(conn, addr)
        except OSError: pass
        finally:
            try: conn.close()
            except OSError: pass
    def handle(self, conn, addr): ...
    def stop(self): self._stop.set()
    @staticmethod
    def recvn(conn, n):
        b = b""
        while len(b) < n:
            try: c = conn.recv(n - len(b))
            except OSError: return None
            if not c: return None
            b += c
        return b


class ModbusDecoy(TCPDecoy):
    protocol = "modbus"
    def __init__(self, *a, critical=None, **k):
        super().__init__(*a, **k)
        self.critical = critical or {"coil": [4], "holding": [3, 4]}
        self.coils = [False]*128; self.di=[False]*128
        self.ir=[4720,6130,890,320,4150]+[0]*123; self.hr=[6000,5500,7000,1000,8500]+[0]*123
    def handle(self, conn, addr):
        while True:
            hdr = self.recvn(conn, 7)
            if not hdr: break
            tid, proto, ln, unit = struct.unpack(">HHHB", hdr)
            pdu = self.recvn(conn, ln-1)
            if not pdu: break
            conn.sendall(struct.pack(">HHHB", tid, 0, len(self._p(addr,unit,pdu))+1, unit)+self._p(addr,unit,pdu))
    def _p(self, addr, unit, pdu):
        f = pdu[0]
        try:
            if f in (1,2,3,4):
                a,c = struct.unpack(">HH", pdu[1:5])
                self.bus.record("modbus", addr, "point-id" if c>4 else "read",
                                f"read fn{f} @{a} x{c} unit{unit}")
                if f in (1,2):
                    src=self.coils if f==1 else self.di; bits=src[a:a+c]; bc=(c+7)//8
                    d=bytearray(bc)
                    for i,b in enumerate(bits):
                        if b: d[i//8]|=1<<(i%8)
                    return struct.pack(">BB", f, bc)+bytes(d)
                src=self.hr if f==3 else self.ir; regs=src[a:a+c]
                return struct.pack(">BB", f, c*2)+b"".join(struct.pack(">H",x) for x in regs)
            if f==5:
                a,raw=struct.unpack(">HH", pdu[1:5]); self.coils[a]=raw==0xFF00
                act="loss-safety" if a in self.critical["coil"] else "manipulate"
                self.bus.record("modbus", addr, act, f"write-coil @{a}={int(self.coils[a])} <<ACTUATION>>")
                return pdu[:5]
            if f==6:
                a,v=struct.unpack(">HH", pdu[1:5]); self.hr[a]=v
                act="loss-safety" if a in self.critical["holding"] else "modify-param"
                self.bus.record("modbus", addr, act, f"write-reg @{a}={v} <<SETPOINT TAMPER>>")
                return pdu[:5]
            if f in (15,16):
                a,c=struct.unpack(">HH", pdu[1:5])
                self.bus.record("modbus", addr, "write", f"bulk write fn{f} @{a} x{c}")
                return struct.pack(">BHH", f, a, c)
            self.bus.record("modbus", addr, "discover", f"unsupported fn 0x{f:02x}")
            return struct.pack(">BB", f|0x80, 1)
        except (struct.error, IndexError):
            return struct.pack(">BB", f|0x80, 2)


class S7Decoy(TCPDecoy):
    protocol = "s7comm"
    def handle(self, conn, addr):
        while True:
            data = conn.recv(512)
            if not data: break
            if len(data) >= 6 and data[0] == 0x03:
                if data[5] == 0xE0:  # COTP connection request
                    conn.sendall(bytes([0x03,0x00,0x00,0x16,0x11,0xD0,0x00,0x01,0x00,0x02,0x00,
                                        0xC0,0x01,0x0A,0xC1,0x02,0x01,0x02,0xC2,0x02,0x01,0x02]))
                    self.bus.record("s7comm", addr, "discover", "COTP connection request (S7 discovery)")
                else:
                    self.bus.record("s7comm", addr, "sysinfo", "S7 job/setup PDU (read/identify attempt)")
                    conn.sendall(data[:4]+b"\x02\xf0\x80")
            else:
                self.bus.record("s7comm", addr, "discover", "non-TPKT probe")


class DNP3Decoy(TCPDecoy):
    protocol = "dnp3"
    def handle(self, conn, addr):
        while True:
            data = conn.recv(512)
            if not data: break
            if data[:2] == b"\x05\x64":            # DNP3 start bytes
                ctrl = data[3] if len(data) > 3 else 0
                self.bus.record("dnp3", addr, "discover",
                                f"DNP3 frame (ctrl=0x{ctrl:02x}) - outstation probe")
                # echo a minimal link-layer ack-ish frame
                conn.sendall(b"\x05\x64\x05\x00" + data[4:8] if len(data) >= 8 else data)
            else:
                self.bus.record("dnp3", addr, "discover", "non-DNP3 probe")


class IEC104Decoy(TCPDecoy):
    protocol = "iec104"
    def handle(self, conn, addr):
        while True:
            data = conn.recv(512)
            if not data: break
            if data[:1] == b"\x68":                # IEC 60870-5-104 APCI start
                # U-frame STARTDT act -> reply STARTDT con
                if len(data) >= 3 and data[2] & 0x07:
                    conn.sendall(b"\x68\x04\x0b\x00\x00\x00")
                self.bus.record("iec104", addr, "discover", "IEC-104 APCI frame (SCADA/RTU probe)")
            else:
                self.bus.record("iec104", addr, "discover", "non-IEC104 probe")


class EtherNetIPDecoy(TCPDecoy):
    protocol = "ethernetip"
    def handle(self, conn, addr):
        while True:
            data = conn.recv(512)
            if not data: break
            if len(data) >= 2:
                cmd = struct.unpack("<H", data[:2])[0]
                if cmd == 0x63:  # ListIdentity
                    self.bus.record("ethernetip", addr, "sysinfo", "ENIP ListIdentity (device fingerprint)")
                    ident = self.profile["product"].encode()[:32]
                    conn.sendall(struct.pack("<HH", 0x63, len(ident)) + b"\x00"*4 + ident)
                elif cmd == 0x65:  # RegisterSession
                    self.bus.record("ethernetip", addr, "discover", "ENIP RegisterSession")
                    conn.sendall(struct.pack("<HH", 0x65, 4) + b"\x00\x00\x00\x00")
                else:
                    self.bus.record("ethernetip", addr, "discover", f"ENIP cmd 0x{cmd:04x}")


class FTPDecoy(TCPDecoy):
    protocol = "ftp"
    def handle(self, conn, addr):
        conn.sendall(f"220 {self.profile['vendor']} PLC FTP service ready\r\n".encode())
        user = ""
        while True:
            data = conn.recv(256)
            if not data: break
            line = data.decode("latin1", "ignore").strip()
            if line.upper().startswith("USER"):
                user = line[5:]; conn.sendall(b"331 Password required\r\n")
            elif line.upper().startswith("PASS"):
                self.bus.record("ftp", addr, "login-attempt",
                                f"FTP creds user='{user}' pass='{line[5:]}' <<DEFAULT/BRUTE>>")
                conn.sendall(b"530 Login incorrect\r\n")
            else:
                conn.sendall(b"502 Command not implemented\r\n")


class TelnetDecoy(TCPDecoy):
    protocol = "telnet"
    def handle(self, conn, addr):
        conn.sendall(f"\r\n{self.profile['product']} maintenance console\r\nlogin: ".encode())
        buf = b""
        while True:
            data = conn.recv(128)
            if not data: break
            buf += data
            if b"\n" in data:
                self.bus.record("telnet", addr, "login-attempt",
                                f"telnet input '{buf.decode('latin1','ignore').strip()[:60]}'")
                conn.sendall(b"Password: ")
                buf = b""


class WebDecoy(TCPDecoy):
    protocol = "web-hmi"
    def handle(self, conn, addr):
        req = conn.recv(4096).decode("latin1", "ignore")
        line = req.split("\r\n", 1)[0]
        path = (line.split(" ") + ["", ""])[1]
        if path.startswith("/token/"):
            self.bus.record("web-hmi", addr, "token-trip",
                            f"HONEYTOKEN triggered: {path} <<planted lure was used!>>")
            body = "<html><body>OK</body></html>"
        elif req.startswith("POST /login"):
            creds = req.split("\r\n\r\n", 1)[-1][:120]
            self.bus.record("web-hmi", addr, "login-attempt", f"web creds '{creds}' <<BRUTE/DEFAULT>>")
            body = "<html><body>Invalid credentials</body></html>"
        else:
            self.bus.record("web-hmi", addr, "read", f"HTTP {line[:60]}")
            body = (f"<!doctype html><title>{self.profile['product']}</title>"
                    f"<body style='font-family:Arial;background:#222;color:#eee'>"
                    f"<h2>{self.profile['vendor']} {self.profile['product']}</h2>"
                    f"<p>Firmware {self.profile['rev']}</p>"
                    f"<form method=POST action=/login>User <input name=user> "
                    f"Password <input type=password name=pass> <button>Sign in</button></form>")
        hdr = (f"HTTP/1.1 200 OK\r\nServer: {self.profile['server']}\r\n"
               f"Content-Type: text/html\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n")
        conn.sendall((hdr + body).encode("latin1"))


# ---- UDP decoys ----
class UDPDecoy(threading.Thread):
    protocol = "udp"
    def __init__(self, host, port, profile, bus):
        super().__init__(daemon=True)
        self.host, self.port, self.profile, self.bus = host, port, profile, bus
        self._stop = threading.Event()
    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: s.bind((self.host, self.port))
        except OSError as e:
            print(f"{C.Y}[!] {self.protocol}/udp {self.port} unavailable ({e}); skipped.{C.RESET}"); return
        s.settimeout(1.0)
        self.bus.decoys_online.append({"protocol": self.protocol, "port": self.port})
        while not self._stop.is_set():
            try: data, addr = s.recvfrom(2048)
            except socket.timeout: continue
            except OSError: break
            try: self.handle(s, data, addr)
            except OSError: pass
        s.close()
    def handle(self, sock, data, addr): ...
    def stop(self): self._stop.set()


class SNMPDecoy(UDPDecoy):
    protocol = "snmp"
    def handle(self, sock, data, addr):
        self.bus.record("snmp", addr, "sysinfo", "SNMP get (device enumeration)")
        # not a full SNMP responder; presence + logging is enough to catch scanners


class BACnetDecoy(UDPDecoy):
    protocol = "bacnet"
    def handle(self, sock, data, addr):
        if data[:1] == b"\x81":  # BVLC
            self.bus.record("bacnet", addr, "discover", "BACnet Who-Is/BVLC (building-automation probe)")


DECOY_REGISTRY = {
    "modbus": (ModbusDecoy, 502), "s7comm": (S7Decoy, 102), "dnp3": (DNP3Decoy, 20000),
    "iec104": (IEC104Decoy, 2404), "ethernetip": (EtherNetIPDecoy, 44818),
    "ftp": (FTPDecoy, 21), "telnet": (TelnetDecoy, 23), "web-hmi": (WebDecoy, 8080),
    "snmp": (SNMPDecoy, 161), "bacnet": (BACnetDecoy, 47808),
}


# ===========================================================================
# Web console (live dashboard)
# ===========================================================================
class Console:
    def __init__(self, bus, host, port):
        self.bus = bus; self.host = host; self.port = port
    def start(self):
        bus = self.bus
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _send(self, code, body, ct="application/json"):
                if isinstance(body, str): body = body.encode("utf-8")
                self.send_response(code); self.send_header("Content-Type", ct+"; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*"); self.end_headers()
                self.wfile.write(body)
            def do_GET(self):
                if self.path in ("/", "/index.html"): self._send(200, DASHBOARD_HTML, "text/html")
                elif self.path.startswith("/api/stats"): self._send(200, json.dumps(bus.snapshot()))
                elif self.path.startswith("/api/intel"):
                    bus._write_intel()
                    self._send(200, json.dumps({"indicators":[s.as_dict() for s in bus.sessions.values() if s.score>=5]}))
                else: self._send(404, "not found", "text/plain")
        httpd = ThreadingHTTPServer((self.host, self.port), H)
        threading.Thread(target=httpd.serve_forever, daemon=True, name="console").start()
        return httpd


# ===========================================================================
# main
# ===========================================================================
DEFAULT_CONFIG = {
    "profile": "siemens_s7_1200",
    "host": "0.0.0.0",
    "console_port": 8888,
    "decoys": ["modbus", "s7comm", "dnp3", "iec104", "ethernetip", "web-hmi", "ftp", "telnet"],
    "log": "mirageot_events.jsonl",
    "block_threshold": 10,
    "response_mode": "alert-only",   # OT-safe default: detect & alert, do NOT auto-drop
    "never_block": [],               # IPs/CIDRs that must never be blocked (assets, scanners)
}


def main():
    ap = argparse.ArgumentParser(description="MirageOT - ICS/OT deception platform")
    ap.add_argument("--config")
    ap.add_argument("--profile", choices=list(PROFILES))
    ap.add_argument("--demo", action="store_true", help="run on safe high ports for a laptop")
    ap.add_argument("--console-port", type=int)
    ap.add_argument("--host")
    args = ap.parse_args()

    cfg = dict(DEFAULT_CONFIG)
    if args.config:
        with open(args.config, encoding="utf-8") as f:
            cfg.update(json.load(f))
    if args.profile: cfg["profile"] = args.profile
    if args.console_port: cfg["console_port"] = args.console_port
    if args.host: cfg["host"] = args.host

    demo_off = 5000 if args.demo else 0   # shift ports up so no root/privs needed
    profile = PROFILES[cfg["profile"]]
    bus = EventBus(cfg)

    print(f"{C.BOLD}{C.CY}")
    print(r"   __  __ _                     ___ _____ ")
    print(r"  |  \/  (_)_ _ __ _ __ _ ___  / _ \_   _|   MirageOT")
    print(r"  | |\/| | | '_/ _` / _` / -_)| (_) || |     ICS/OT Deception Platform v"+VERSION)
    print(r"  |_|  |_|_|_| \__,_\__, \___| \___/ |_|     open-source | FortiDeceptor-class")
    print(r"                    |___/                    "+C.RESET)
    print(f"{C.GR}   posing as: {profile['vendor']} {profile['product']} (fw {profile['rev']}){C.RESET}\n")

    decoys = []
    for name in cfg["decoys"]:
        if name not in DECOY_REGISTRY:
            print(f"{C.Y}[!] unknown decoy '{name}' - skipped{C.RESET}"); continue
        klass, defport = DECOY_REGISTRY[name]
        port = defport + demo_off
        kwargs = {}
        if name == "modbus":
            kwargs["critical"] = cfg.get("critical_points", {"coil": [4], "holding": [3, 4]})
        d = klass(cfg["host"], port, profile, bus, **kwargs)
        d.start(); decoys.append(d)
        print(f"{C.G}[+] decoy {name:<11} :{port}{C.RESET}")

    console = Console(bus, cfg["host"], cfg["console_port"] + demo_off).start()
    curl = f"http://127.0.0.1:{cfg['console_port'] + demo_off}"
    print(f"\n{C.YEL_BG} DECEPTION GRID ARMED {C.RESET}  live console: {C.BOLD}{curl}{C.RESET}")
    print(f"{C.GR}   log: {cfg['log']} | blocklist: {bus.blocklist_path} | "
          f"intel: {bus.intel_path}{C.RESET}")
    print(f"{C.GR}   waiting for attackers... (Ctrl+C to stop){C.RESET}\n")

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for d in decoys: d.stop()
        console.shutdown()
        bus._write_intel()
        snap = bus.snapshot()
        print(f"\n{C.BOLD}== MirageOT summary =={C.RESET}")
        print(f"   attackers: {snap['totals']['attackers']} | events: {snap['totals']['events']} | "
              f"auto-blocked: {snap['totals']['blocked']}")
        print(f"   threat intel written to {bus.intel_path}")


# The dashboard is a self-contained page that polls /api/stats every 2s.
DASHBOARD_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MirageOT — Deception Console</title><style>
:root{--bg:#0b1017;--card:#141d29;--card2:#1b2836;--line:#26384c;--ink:#e8eef5;--soft:#9fb0c3;
--mut:#6d8197;--ac:#3fc7b4;--bl:#4a9eff;--gd:#e8b93f;--dg:#ef5a5a;--ok:#5fd08a}
*{box-sizing:border-box}body{margin:0;font-family:'Segoe UI',Arial,sans-serif;background:var(--bg);color:var(--ink)}
.top{display:flex;justify-content:space-between;align-items:center;padding:14px 22px;border-bottom:1px solid var(--line);background:#0d141d;position:sticky;top:0}
.brand{font-weight:800;font-size:1.15rem;letter-spacing:.5px}.brand b{color:var(--ac)}
.brand .v{color:var(--mut);font-size:.7rem;font-weight:400;margin-left:6px}
.pills{display:flex;gap:8px;color:var(--soft);font-size:.8rem}.pill{background:var(--card2);border:1px solid var(--line);border-radius:999px;padding:5px 12px}
.wrap{max-width:1200px;margin:0 auto;padding:18px 22px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
@media(max-width:800px){.cards{grid-template-columns:repeat(2,1fr)}}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
.kpi .n{font-size:2rem;font-weight:800}.kpi .l{color:var(--mut);font-size:.78rem}
.kpi.dg .n{color:var(--dg)}.kpi.gd .n{color:var(--gd)}.kpi.ac .n{color:var(--ac)}.kpi.bl .n{color:var(--bl)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
.panel h3{margin:0 0 12px;font-size:.95rem}
.bar{display:flex;align-items:center;gap:8px;margin:5px 0;font-size:.82rem}
.bar .lb{width:90px;color:var(--soft)}.bar .tr{flex:1;background:var(--card2);border-radius:6px;height:14px;overflow:hidden}
.bar .fl{height:100%;background:linear-gradient(90deg,var(--ac),var(--bl))}.bar .vv{width:34px;text-align:left;color:var(--soft)}
table{width:100%;border-collapse:collapse;font-size:.8rem}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:600}
.chip{display:inline-block;font-size:.68rem;padding:2px 7px;border-radius:5px;margin:2px;background:var(--card2);border:1px solid var(--line);color:var(--soft)}
.stage{font-size:.66rem;padding:2px 7px;border-radius:5px}
.stage.RECON{background:rgba(74,158,255,.18);color:#9fd0ff}.stage.INTERACTION{background:rgba(232,185,63,.18);color:#f0d888}
.stage.MANIPULATION{background:rgba(239,90,90,.2);color:#ffb3b3}
.feed{max-height:340px;overflow-y:auto;font-family:Consolas,monospace;font-size:.75rem}
.ev{padding:4px 6px;border-bottom:1px solid rgba(38,56,76,.5);display:flex;gap:8px}
.ev .s{width:64px}.sev-LOW{color:var(--mut)}.sev-MEDIUM{color:var(--gd)}.sev-HIGH{color:var(--dg)}.sev-CRITICAL{color:#fff;background:var(--dg);padding:0 4px;border-radius:3px}
.mut{color:var(--mut)}.live{width:9px;height:9px;border-radius:50%;background:var(--ok);display:inline-block;box-shadow:0 0 10px var(--ok);animation:p 1.5s infinite}
@keyframes p{50%{opacity:.4}}
</style></head><body>
<div class="top"><div class="brand"><span class="live"></span> Mirage<b>OT</b> <span class="v">Deception Console</span></div>
<div class="pills"><span class="pill" id="p-decoys">decoys: —</span><span class="pill" id="p-up">uptime: —</span></div></div>
<div class="wrap">
<div class="cards">
  <div class="kpi ac"><div class="n" id="k-ev">0</div><div class="l">Total interactions</div></div>
  <div class="kpi gd"><div class="n" id="k-atk">0</div><div class="l">Unique attackers</div></div>
  <div class="kpi dg"><div class="n" id="k-man">0</div><div class="l">In manipulation stage</div></div>
  <div class="kpi bl"><div class="n" id="k-blk">0</div><div class="l">Auto-blocked IPs</div></div>
</div>
<div class="grid">
  <div class="panel"><h3>Decoys hit (by protocol)</h3><div id="proto"></div></div>
  <div class="panel"><h3>MITRE ATT&CK for ICS — techniques observed</h3><div id="mitre"></div></div>
</div>
<div class="grid">
  <div class="panel"><h3>Top attackers</h3><div style="overflow-x:auto"><table id="tatk">
    <tr><th>Source IP</th><th>Stage</th><th>Score</th><th>Events</th><th>Decoys</th><th>Last seen</th></tr></table></div></div>
  <div class="panel"><h3>Live event feed</h3><div class="feed" id="feed"></div></div>
</div>
</div>
<script>
const $=i=>document.getElementById(i);
function fmtUp(s){const h=(s/3600|0),m=((s%3600)/60|0);return h+"h "+m+"m";}
async function tick(){
 let d; try{d=await (await fetch('/api/stats')).json();}catch(e){return;}
 $('k-ev').textContent=d.totals.events;$('k-atk').textContent=d.totals.attackers;
 $('k-man').textContent=d.totals.manipulation;$('k-blk').textContent=d.totals.blocked;
 $('p-decoys').textContent='decoys online: '+d.decoys_online.length;
 $('p-up').textContent='uptime: '+fmtUp(d.uptime);
 const mx=Math.max(1,...Object.values(d.by_protocol));
 $('proto').innerHTML=Object.entries(d.by_protocol).sort((a,b)=>b[1]-a[1]).map(([k,v])=>
   `<div class="bar"><span class="lb">${k}</span><span class="tr"><span class="fl" style="width:${v/mx*100}%"></span></span><span class="vv">${v}</span></div>`).join('')||'<span class="mut">no activity yet</span>';
 $('mitre').innerHTML=d.techniques.map(t=>`<span class="chip">${t.id} · ${t.name}</span>`).join('')||'<span class="mut">none observed</span>';
 $('tatk').innerHTML='<tr><th>Source IP</th><th>Stage</th><th>Score</th><th>Events</th><th>Decoys</th><th>Last seen</th></tr>'+
   d.top_attackers.map(a=>`<tr><td><b>${a.ip}</b></td><td><span class="stage ${a.stage}">${a.stage}</span></td>
   <td>${a.score}</td><td>${a.events}</td><td class="mut">${a.decoys.join(', ')}</td><td class="mut">${a.last_seen.replace('T',' ')}</td></tr>`).join('');
 $('feed').innerHTML=d.recent.map(e=>`<div class="ev"><span class="s sev-${e.severity}">${e.severity}</span>
   <span class="mut">${e.time.split('T')[1]}</span><b>${e.protocol}</b><span class="mut">${e.src_ip}</span>${e.action} — ${e.detail}</div>`).join('');
}
tick();setInterval(tick,2000);
</script></body></html>"""


if __name__ == "__main__":
    main()
