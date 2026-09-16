#!/usr/bin/env python3
"""
MirageOT Lure Forge - generate deception tokens (breadcrumbs) to plant on REAL assets.

Deception platforms also scatter "lures": fake credentials, bookmarks and honeytokens on real
endpoints so an attacker who lands there is guided straight to a decoy. When they take
the bait, the decoy fires a CRITICAL alert.

This tool creates a folder of ready-to-plant lures pointing at your MirageOT decoys.

Usage:
    python gen_tokens.py --decoy-ip 10.0.2.50 --console http://10.0.3.10:8888
Then plant the files in ./lures/ on jump hosts / engineering workstations / file shares.
Any use of a planted honeytoken URL shows up in the console as a `token-trip` (CRITICAL).
"""
import argparse
import json
import os
import secrets


def main():
    ap = argparse.ArgumentParser(description="MirageOT deception token generator")
    ap.add_argument("--decoy-ip", default="10.0.2.50", help="IP of a MirageOT decoy PLC")
    ap.add_argument("--web-port", type=int, default=8080)
    ap.add_argument("--console", default="http://127.0.0.1:8888", help="MirageOT console URL for the manifest")
    ap.add_argument("--modbus-port", type=int, default=502)
    ap.add_argument("--out", default="lures")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    tok = secrets.token_hex(6)
    honeytoken_url = f"http://{args.decoy_ip}:{args.web_port}/token/{tok}"
    manifest = {"token": tok, "honeytoken_url": honeytoken_url,
                "decoy_ip": args.decoy_ip, "console": args.console, "lures": []}

    def write(name, content, note):
        path = os.path.join(args.out, name)
        with open(path, "w", encoding="utf-8", newline="\r\n") as f:
            f.write(content)
        manifest["lures"].append({"file": name, "plant_on": note})
        print(f"  [+] {name:<26} -> plant on: {note}")

    # 1) Fake credentials file (attackers grep for these)
    write("plc_credentials.txt",
          f"# SCADA / PLC access - DO NOT SHARE\n"
          f"HMI Web:   {honeytoken_url.rsplit('/token',1)[0]}/\n"
          f"PLC IP:    {args.decoy_ip}\n"
          f"user: engineer\npassword: Plant@2024!\n"
          f"backup portal: {honeytoken_url}\n",
          "engineering workstation Desktop / shared drive")

    # Browser bookmark (Netscape format) with the honeytoken URL
    write("plc_bookmarks.html",
          "<!DOCTYPE NETSCAPE-Bookmark-file-1><DL>\n"
          f'<DT><A HREF="{honeytoken_url.rsplit("/token",1)[0]}/">PLC HMI (Pump Station)</A>\n'
          f'<DT><A HREF="{honeytoken_url}">PLC Firmware Backup Portal</A>\n</DL>\n',
          "operator browser bookmarks import")

    # A honeytoken 'firmware download' note
    write("firmware_backup.url",
          f"[InternetShortcut]\r\nURL={honeytoken_url}\r\n",
          "file server 'Backups' folder")

    # Fake connection profile for engineering software
    write("station_profile.json", json.dumps({
        "station": "Pump Station #3", "plc": args.decoy_ip, "protocol": "Modbus/TCP",
        "port": args.modbus_port, "web_hmi": honeytoken_url, "notes": "primary controller"}, indent=2),
        "engineering software project folder")

    with open(os.path.join(args.out, "MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nHoneytoken URL (fires CRITICAL when used): {honeytoken_url}")
    print(f"Lures written to ./{args.out}/  -  plant them, then watch the MirageOT console.")
    print("Investigate any hit and verify the source before responding.")


if __name__ == "__main__":
    main()
