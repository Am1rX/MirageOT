"""Command-line entry point and service lifecycle."""

import argparse
import json
import os
import signal
import threading

from .config import DEFAULT_CONFIG, PORTS, PROFILES, validate
from .console import Console
from .events import EventBus
from .protocols.ancillary import FTPDecoy, TelnetDecoy, WebDecoy
from .protocols.industrial import (BACnetDecoy, DNP3Decoy, EtherNetIPDecoy,
                                   IEC104Decoy, S7Decoy, SNMPDecoy)
from .protocols.modbus import ModbusDecoy

REGISTRY = {"modbus": ModbusDecoy, "s7comm": S7Decoy, "dnp3": DNP3Decoy,
            "iec104": IEC104Decoy, "ethernetip": EtherNetIPDecoy,
            "web-hmi": WebDecoy, "ftp": FTPDecoy, "telnet": TelnetDecoy,
            "snmp": SNMPDecoy, "bacnet": BACnetDecoy}


def load_config(args):
    cfg = dict(DEFAULT_CONFIG)
    if args.config:
        with open(args.config, encoding="utf-8") as fh:
            user = json.load(fh)
        if not isinstance(user, dict):
            raise ValueError("config must be a JSON object")
        unknown = {key for key in user if not key.startswith("_")} - DEFAULT_CONFIG.keys() - {"syslog", "webhook"}
        if unknown:
            raise ValueError("unknown config keys: " + ", ".join(sorted(unknown)))
        cfg.update({key: value for key, value in user.items() if not key.startswith("_")})
    for option in ("profile", "host", "console_host", "console_port"):
        value = getattr(args, option)
        if value is not None:
            cfg[option] = value
    cfg["console_token"] = os.environ.get("MIRAGEOT_CONSOLE_TOKEN", "")
    if args.demo and args.host is None:
        cfg["host"] = "127.0.0.1"
    validate(cfg)
    offset = 5000 if args.demo else 0
    if any(PORTS[name] + offset > 65535 for name in cfg["decoys"]):
        raise ValueError("demo port exceeds 65535")
    if cfg["console_port"] + offset > 65535:
        raise ValueError("demo console port exceeds 65535")
    return cfg, offset


def main(argv=None):
    parser = argparse.ArgumentParser(description="MirageOT industrial deception sensor")
    parser.add_argument("--config")
    parser.add_argument("--profile", choices=PROFILES)
    parser.add_argument("--host")
    parser.add_argument("--console-host")
    parser.add_argument("--console-port", type=int)
    parser.add_argument("--demo", action="store_true", help="shift service ports by 5000")
    args = parser.parse_args(argv)
    try:
        cfg, offset = load_config(args)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    bus = EventBus(cfg)
    decoys = []
    console = None
    shutdown = threading.Event()

    def request_stop(_signum, _frame):
        shutdown.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(signum, request_stop)
        except ValueError:
            pass
    try:
        for name in cfg["decoys"]:
            port = PORTS[name] + offset
            decoy = REGISTRY[name](cfg["host"], port, PROFILES[cfg["profile"]], bus)
            decoy.start()
            decoy.ready.wait(timeout=3)
            if decoy.bound:
                decoys.append(decoy)
                print("[+] {} listening on {}:{}".format(name, cfg["host"], port))
        if not decoys:
            raise RuntimeError("no decoy could bind")
        console = Console(bus, cfg["console_host"], cfg["console_port"] + offset,
                          cfg["console_token"] or None).start()
        print("MirageOT console: http://{}:{}".format(cfg["console_host"], cfg["console_port"] + offset))
        print("Response mode: {}. Press Ctrl+C to stop.".format(cfg["response_mode"]))
        shutdown.wait()
    except KeyboardInterrupt:
        pass
    finally:
        for decoy in decoys:
            decoy.stop()
        for decoy in decoys:
            decoy.join(timeout=2)
        if console:
            console.close()
        bus.close()
        print("MirageOT stopped; {} events written".format(bus.snapshot()["totals"]["events"]))
