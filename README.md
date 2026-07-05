# 🛰️ MirageOT — Open-Source ICS/OT Deception Platform

> A multi-protocol industrial **deception grid** that stands next to commercial
> platforms like **FortiDeceptor**, TrapX and Attivo — but open, hackable, and free.
> Deploy decoy PLCs, lure attackers with breadcrumbs, watch them on a live console,
> auto-block them, and feed your SIEM. **Python stdlib only. Zero dependencies.**

```
   __  __ _                     ___ _____
  |  \/  (_)_ _ __ _ __ _ ___  / _ \_   _|
  | |\/| | | '_/ _` / _` / -_)| (_) || |     ICS/OT Deception Platform
  |_|  |_|_|_| \__,_\__, \___| \___/ |_|     open-source · FortiDeceptor-class
                    |___/
```

## ✨ Features
- **10 protocol decoys** — Modbus, S7comm, DNP3, IEC 60870-5-104, EtherNet/IP,
  BACnet, SNMP, FTP, Telnet, Web-HMI — impersonating real Siemens/Schneider/AB/GE PLCs.
- **Attacker session correlation** with a rising **threat score** and a kill-chain
  **stage** (`RECON → INTERACTION → MANIPULATION`).
- **MITRE ATT&CK for ICS** technique tagging on every event (T0846, T0855, T0880…).
- **Live web console** (dashboard) — KPIs, protocol breakdown, technique chips,
  top-attacker table, real-time event feed. Perfect for the SOC (and screenshots).
- **Deception tokens / lures** (`gen_tokens.py`) — plantable fake creds, RDP files,
  bookmarks and **honeytokens** that fire a CRITICAL alert when touched.
- **Automated response** — hostile IPs (score ≥ threshold) are written to a
  firewall-ingestable **blocklist**, and exported as **threat intel** (IOCs).
- **SIEM + SOAR integration** — CEF/syslog and Slack/Teams/webhook out of the box.

## 🥊 How it compares
| Capability | FortiDeceptor | TrapX / Attivo | **MirageOT** |
|---|:---:|:---:|:---:|
| OT/ICS protocol decoys | ✅ | ✅ | ✅ (10 protocols) |
| Multi-decoy orchestration | ✅ | ✅ | ✅ |
| Lures / breadcrumbs / tokens | ✅ | ✅ | ✅ |
| Attacker timeline & scoring | ✅ | ✅ | ✅ |
| MITRE ATT&CK for ICS mapping | ✅ | partial | ✅ |
| Live SOC dashboard | ✅ | ✅ | ✅ |
| SIEM (CEF) integration | ✅ | ✅ | ✅ |
| Automated quarantine/response | ✅ (FortiGate) | ✅ | ✅ (blocklist/webhook) |
| Threat-intel export | ✅ | ✅ | ✅ (JSON IOCs) |
| Runs on a $0 budget / air-gap-friendly | ❌ | ❌ | ✅ |
| Auditable source you fully control | ❌ | ❌ | ✅ |
| Full high-fidelity PLC emulation | ✅ | ✅ | ⚠️ decoy-level (by design) |

> MirageOT is a **medium-interaction** deception grid: it answers discovery/interaction
> probes and logs everything with high fidelity — the sweet spot for a tripwire. It
> does not fully emulate proprietary firmware (neither do most honeypots).

## 🚀 Quick start (laptop, safe high ports)
```bash
python mirageot.py --demo
#  -> decoys on 5502/5102/25000/... , console on http://127.0.0.1:13888
```
Open the console URL, then poke a decoy and watch it light up:
```bash
python - <<'PY'
import socket, struct
s=socket.create_connection(("127.0.0.1",5502))          # modbus decoy
s.sendall(struct.pack(">HHHB",1,0,6,1)+struct.pack(">BHH",5,0,0xFF00))  # write coil
print(s.recv(64)); s.close()
PY
```

## 🏭 Production deployment
```bash
cp config.example.json config.json     # edit profile, decoys, SIEM, thresholds
sudo python mirageot.py --config config.json     # real ports (502,102,...) need CAP_NET_BIND_SERVICE
```
Use the provided `Dockerfile` and `mirageot.service`. Then plant lures:
```bash
python gen_tokens.py --decoy-ip 10.0.2.50 --console http://10.0.3.10:8888
# -> ./lures/  (plant on jump hosts / shares; any use fires a CRITICAL token-trip)
```

## 🧭 Where it fits (defense in depth)
```
   ═══════ Industrial DMZ (IEC 62443) ═══════
     [ MirageOT decoys + console ]  ← deception / early warning
     [ SIEM ]  ←CEF── from MirageOT & OT-Sentinel IDS
   ─────────── OT zones (real assets) ───────────
```
Pair it with **OT-Sentinel** (`../passive_ids/`) for detection and an OT firewall for
prevention. See `docs/09-appliances-and-architecture.md`.

## 🚦 Automated response — the OT-safe way (read this)
In OT, **availability and safety outrank everything**. Auto-blocking an IP at the
firewall can *itself* cause an outage — if the "attacker" turns out to be a real HMI
(misconfigured, or compromised and used to pivot), dropping its traffic removes operator
visibility/control, which is a safety event. So MirageOT does **not** blindly block.

- **Default `response_mode: "alert-only"`** — MirageOT raises a high-fidelity alert and
  prints a `REVIEW` recommendation, but **never drops traffic**. A human triages first.
- **`never_block`** — a list of IPs/CIDRs (your OT asset subnets, engineering stations,
  and your own asset/vuln scanners) that are **never** auto-blocked, even in blocklist
  mode. They still *alert* (a legit box touching a decoy is a strong IOC worth
  investigating), but their traffic is never cut.
- **`response_mode: "blocklist"`** — opt-in, and even then only **untrusted** sources
  (not on `never_block`) are written to the blocklist. Best scoped to IT/external source
  ranges at the IT↔DMZ boundary, never deep inside an OT cell.

Rule of thumb: **detect automatically, block manually** for anything that could be a
production or safety asset. See the FAQ in the root README for the full reasoning.

## ⚠️ Safety & ethics
Deploy only on networks you own/are authorized to run. Put MirageOT on an **isolated,
monitored** segment (its own VLAN) with **egress = drop-all** except your log collector —
a honeypot must never be able to pivot into real assets. Never let it confuse a real
polling master or operator.

## 📁 Files
| File | Purpose |
|---|---|
| `mirageot.py` | the platform: decoys + correlation + console + response |
| `gen_tokens.py` | deception token / lure generator |
| `ics_honeypot.py` | minimal single-file honeypot (the simpler predecessor) |
| `config.example.json` | production config template |
| `Dockerfile`, `mirageot.service` | deployment |
| `ARTICLE.md` | ready-to-publish Medium write-up |
