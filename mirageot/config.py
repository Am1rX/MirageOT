"""Configuration, device profiles, and startup validation."""

import ipaddress

PROFILES = {
    "siemens_s7_1200": {"vendor": "Siemens", "product": "SIMATIC S7-1200 CPU 1214C", "rev": "V4.2.3", "server": "Siemens SIMATIC", "sys": "Siemens SIMATIC S7-1200"},
    "schneider_m340": {"vendor": "Schneider Electric", "product": "Modicon M340 BMXP342020", "rev": "2.60", "server": "Schneider-WEB/V2.1", "sys": "Schneider Modicon M340"},
    "allen_bradley": {"vendor": "Rockwell/Allen-Bradley", "product": "MicroLogix 1400", "rev": "21.003", "server": "A-B WWW/1.0", "sys": "Allen-Bradley MicroLogix 1400"},
    "ge_rx3i": {"vendor": "GE", "product": "PACSystems RX3i", "rev": "9.75", "server": "GE-HTTP/1.0", "sys": "GE PACSystems RX3i"},
}

DEFAULT_CONFIG = {
    "profile": "siemens_s7_1200",
    "host": "0.0.0.0",
    "console_host": "127.0.0.1",
    "console_port": 8888,
    "decoys": ["modbus", "s7comm", "dnp3", "iec104", "ethernetip", "web-hmi", "ftp", "telnet"],
    "log": "mirageot_events.jsonl",
    "intel": "threat_intel.json",
    "blocklist": "blocklist.txt",
    "response_mode": "alert-only",
    "block_threshold": 20,
    "never_block": [],
    "critical_points": {"coil": [4], "holding": [3, 4]},
    "max_clients_per_decoy": 64,
}

PORTS = {"modbus": 502, "s7comm": 102, "dnp3": 20000, "iec104": 2404,
         "ethernetip": 44818, "web-hmi": 8080, "ftp": 21, "telnet": 23,
         "snmp": 161, "bacnet": 47808}


def validate(cfg):
    """Reject unsafe or contradictory deployment settings before binding sockets."""
    if cfg.get("profile") not in PROFILES:
        raise ValueError("unknown device profile")
    if not isinstance(cfg.get("decoys"), list) or not cfg["decoys"]:
        raise ValueError("decoys must be a non-empty list")
    if len(cfg["decoys"]) != len(set(cfg["decoys"])) or set(cfg["decoys"]) - PORTS.keys():
        raise ValueError("decoys contains duplicate or unknown service")
    if cfg.get("response_mode") not in ("alert-only", "blocklist"):
        raise ValueError("response_mode must be alert-only or blocklist")
    for name in ("console_port", "block_threshold", "max_clients_per_decoy"):
        value = cfg.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(name + " must be a positive integer")
    if cfg["console_port"] > 65535:
        raise ValueError("console_port exceeds 65535")
    if not 1 <= cfg["max_clients_per_decoy"] <= 1024:
        raise ValueError("max_clients_per_decoy must be 1..1024")
    for item in cfg.get("never_block", []):
        ipaddress.ip_network(item, strict=False)
    for kind in ("coil", "holding"):
        addresses = cfg.get("critical_points", {}).get(kind, [])
        if not isinstance(addresses, list) or any(not isinstance(x, int) or not 0 <= x < 128 for x in addresses):
            raise ValueError("critical_points." + kind + " must contain register indices 0..127")
    console_host = cfg.get("console_host", "127.0.0.1")
    if not ipaddress.ip_address(console_host).is_loopback and not cfg.get("console_token"):
        raise ValueError("remote console binding requires MIRAGEOT_CONSOLE_TOKEN")
    if cfg.get("console_token") and len(cfg["console_token"]) < 16:
        raise ValueError("console token must have at least 16 characters")
    return cfg
