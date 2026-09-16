"""Bounded session state, structured events, and OT-safe response policy."""

import ipaddress
import json
import os
import queue
import socket
import threading
import time
from collections import Counter, OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path

# ATT&CK for ICS is an analytic interpretation, not proof of attacker intent.
# Map only actions that have enough protocol context. Version reviewed: Sep 2026.
# https://attack.mitre.org/matrices/ics/
TECHNIQUES = {
    "read": ("T0801", "Monitor Process State"),
    "sysinfo": ("T0888", "Remote System Information Discovery"),
    "modify-param": ("T0836", "Modify Parameter"),
    "manipulate": ("T0831", "Manipulation of Control"),
    "critical-write-attempt": ("T0831", "Manipulation of Control"),
}
ACTION_META = {
    "connect": ("LOW", 1), "discover": ("LOW", 2), "read": ("LOW", 2),
    "sysinfo": ("MEDIUM", 3), "invalid-frame": ("MEDIUM", 2),
    "write": ("HIGH", 8), "modify-param": ("HIGH", 10),
    "manipulate": ("HIGH", 12), "critical-write-attempt": ("CRITICAL", 20),
    "login-attempt": ("MEDIUM", 5), "token-trip": ("CRITICAL", 20),
}


def utc(ts=None):
    return datetime.fromtimestamp(ts if ts is not None else time.time(), timezone.utc).isoformat(timespec="seconds")


class Session:
    def __init__(self, ip, ts):
        self.ip, self.first, self.last = ip, ts, ts
        self.events = self.score = 0
        self.decoys = set()
        self.actions = Counter()
        self.techniques = {}

    def stage(self):
        return "MANIPULATION" if self.score >= 20 else "INTERACTION" if self.score >= 8 else "RECON"

    def as_dict(self):
        return {"ip": self.ip, "first_seen": utc(self.first), "last_seen": utc(self.last),
                "events": self.events, "score": self.score, "stage": self.stage(),
                "decoys": sorted(self.decoys), "actions": dict(self.actions),
                "techniques": [{"id": k, "name": v} for k, v in self.techniques.items()]}


class EventBus:
    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.RLock()
        self.intel_lock = threading.Lock()
        self.log_path = Path(cfg["log"])
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_fh = self.log_path.open("a", encoding="utf-8")
        self.sessions = OrderedDict()
        self.recent = deque(maxlen=400)
        self.stats, self.by_protocol, self.by_severity = Counter(), Counter(), Counter()
        self.started = time.time()
        self.decoys_online = []
        self.protected = [ipaddress.ip_network(x, strict=False) for x in cfg.get("never_block", [])]
        self.recommended = set()
        self.blocked = self._read_blocklist()
        self.outbound = queue.Queue(maxsize=512)
        self._closing = threading.Event()
        self._worker = threading.Thread(target=self._send_loop, daemon=True, name="mirageot-alerts")
        self._worker.start()

    def _read_blocklist(self):
        path = Path(self.cfg["blocklist"])
        if not path.exists():
            return set()
        return {line.partition("#")[0].strip() for line in path.read_text(encoding="utf-8").splitlines()
                if line.partition("#")[0].strip()}

    def record(self, protocol, src, action, detail):
        ip = src[0] if isinstance(src, tuple) else str(src)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            ip = "0.0.0.0"
        now = time.time()
        severity, weight = ACTION_META.get(action, ("MEDIUM", 3))
        tech = TECHNIQUES.get(action)
        rec = {"time": utc(now), "protocol": protocol, "src_ip": ip, "action": action,
               "detail": str(detail)[:512], "severity": severity,
               "technique": {"id": tech[0], "name": tech[1]} if tech else None}
        with self.lock:
            # Bound memory during sustained scans, preserving the most recently touched IPs.
            session = self.sessions.pop(ip, None)
            if session is None or now - session.last > 86400:
                session = Session(ip, now)
            session.last = now
            session.events += 1
            session.score += weight
            session.decoys.add(protocol)
            session.actions[action] += 1
            if tech:
                session.techniques[tech[0]] = tech[1]
            self.sessions[ip] = session
            if len(self.sessions) > 4096:
                old_ip, _ = self.sessions.popitem(last=False)
                self.recommended.discard(old_ip)
            rec["session_score"], rec["session_stage"] = session.score, session.stage()
            self.stats[action] += 1
            self.by_protocol[protocol] += 1
            self.by_severity[severity] += 1
            self.recent.appendleft(rec)
            self.log_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.log_fh.flush()
            if session.score >= self.cfg["block_threshold"] and ip not in self.recommended:
                self.recommended.add(ip)
                if self.cfg["response_mode"] == "blocklist" and not self._is_protected(ip):
                    self._append_block(ip, session)
                else:
                    print("[REVIEW] {} reached score {}; investigate source before action".format(ip, session.score))
                self.write_intel()
        if self.cfg.get("syslog") or (self.cfg.get("webhook") and severity in ("HIGH", "CRITICAL")):
            try:
                self.outbound.put_nowait(rec)
            except queue.Full:
                print("[WARN] alert queue full; event remains in local log")
        return rec

    def _is_protected(self, ip):
        return any(ipaddress.ip_address(ip) in network for network in self.protected)

    def _append_block(self, ip, session):
        if ip in self.blocked:
            return
        path = Path(self.cfg["blocklist"])
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write("{} # score={} at {}\n".format(ip, session.score, utc()))
        self.blocked.add(ip)
        print("[BLOCKLIST] {} added; external firewall integration must apply changes".format(ip))

    def write_intel(self):
        with self.lock:
            data = {"generated": utc(), "sensor": "MirageOT", "indicators":
                    [s.as_dict() for s in self.sessions.values() if s.score >= 5]}
        with self.intel_lock:
            path = Path(self.cfg["intel"])
            path.parent.mkdir(parents=True, exist_ok=True)
            temp = path.with_name(path.name + ".tmp")
            temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(temp, path)
        return data

    def snapshot(self):
        with self.lock:
            top = sorted(self.sessions.values(), key=lambda s: -s.score)[:12]
            techniques = {k: v for s in self.sessions.values() for k, v in s.techniques.items()}
            return {"version": "2.0.0", "uptime": int(time.time() - self.started),
                    "decoys_online": list(self.decoys_online),
                    "totals": {"events": sum(self.stats.values()), "attackers": len(self.sessions),
                               "manipulation": sum(s.stage() == "MANIPULATION" for s in self.sessions.values()),
                               "blocked": len(self.blocked)},
                    "by_protocol": dict(self.by_protocol), "by_severity": dict(self.by_severity),
                    "techniques": [{"id": k, "name": v} for k, v in techniques.items()],
                    "top_attackers": [s.as_dict() for s in top], "recent": list(self.recent)[:60]}

    def _send_loop(self):
        import urllib.request
        while not self._closing.is_set() or not self.outbound.empty():
            try:
                rec = self.outbound.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                syslog = self.cfg.get("syslog")
                if syslog:
                    host, sep, port = syslog.rpartition(":")
                    if not sep:
                        host, port = syslog, "514"
                    # Escape CEF delimiter and extension characters from untrusted traffic.
                    clean = lambda v: str(v).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", " ").replace("\r", " ")
                    severity = {"LOW": 3, "MEDIUM": 6, "HIGH": 8, "CRITICAL": 10}[rec["severity"]]
                    cef = "CEF:0|MirageOT|Sensor|2.0|{}|{}|{}|src={} app={} cs1Label=MitreID cs1={}".format(
                        clean(rec["action"]), clean(rec["detail"]), severity,
                        clean(rec["src_ip"]), clean(rec["protocol"]),
                        clean((rec["technique"] or {}).get("id", "")))
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.sendto(cef.encode("utf-8"), (host, int(port)))
                if self.cfg.get("webhook") and rec["severity"] in ("HIGH", "CRITICAL"):
                    payload = json.dumps({"text": "[MirageOT] {} {} {} from {}".format(
                        rec["severity"], rec["protocol"], rec["action"], rec["src_ip"])}).encode()
                    request = urllib.request.Request(self.cfg["webhook"], data=payload,
                                                     headers={"Content-Type": "application/json"})
                    urllib.request.urlopen(request, timeout=3).close()
            except Exception as exc:
                print("[WARN] alert delivery failed: {}".format(exc))
            finally:
                self.outbound.task_done()

    def close(self):
        self._closing.set()
        self._worker.join(timeout=5)
        self.write_intel()
        with self.lock:
            self.log_fh.close()
