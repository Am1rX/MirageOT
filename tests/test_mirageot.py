import json
import argparse
import socket
import struct
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from mirageot.config import DEFAULT_CONFIG, PROFILES, validate
from mirageot.cli import load_config
from mirageot.console import Console
from mirageot.events import EventBus
from mirageot.protocols.industrial import EtherNetIPDecoy, IEC104Decoy, S7Decoy
from mirageot.protocols.modbus import ModbusDecoy


class FakeBus:
    def __init__(self):
        self.cfg = dict(DEFAULT_CONFIG)
        self.events = []
        self.lock = threading.RLock()
        self.decoys_online = []

    def record(self, protocol, addr, action, detail):
        self.events.append((protocol, action, detail))


class ModbusTests(unittest.TestCase):
    def setUp(self):
        self.bus = FakeBus()
        self.modbus = ModbusDecoy("127.0.0.1", 0, PROFILES["siemens_s7_1200"], self.bus)
        self.addr = ("127.0.0.1", 12000)

    def test_valid_read_and_write(self):
        write = struct.pack(">BHH", 6, 3, 4321)
        self.assertEqual(self.modbus.process_pdu(self.addr, 1, write), write)
        self.assertEqual(self.bus.events[-1][1], "critical-write-attempt")
        result = self.modbus.process_pdu(self.addr, 1, struct.pack(">BHH", 3, 3, 1))
        self.assertEqual(result, b"\x03\x02" + struct.pack(">H", 4321))

    def test_bulk_write_changes_state_and_checks_critical_range(self):
        request = struct.pack(">BHHBHH", 16, 2, 2, 4, 12, 13)
        self.assertEqual(self.modbus.process_pdu(self.addr, 1, request), struct.pack(">BHH", 16, 2, 2))
        self.assertEqual(self.modbus.holding[2:4], [12, 13])
        self.assertEqual(self.bus.events[-1][1], "critical-write-attempt")

    def test_bad_requests_do_not_mutate_or_claim_write(self):
        before = list(self.modbus.holding)
        bad = [b"\x06\x00", struct.pack(">BHH", 6, 128, 9),
               struct.pack(">BHHB", 16, 0, 2, 1) + b"\x00"]
        for request in bad:
            result = self.modbus.process_pdu(self.addr, 1, request)
            self.assertEqual(result[0] & 0x80, 0x80)
        self.assertEqual(self.modbus.holding, before)
        self.assertEqual(self.bus.events, [])

    def test_split_tcp_frame_and_invalid_mbap(self):
        decoy = self.modbus
        decoy.start()
        self.assertTrue(decoy.ready.wait(2))
        self.assertTrue(decoy.bound)
        port = decoy.server.getsockname()[1]
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                request = struct.pack(">HHHB", 7, 0, 6, 1) + struct.pack(">BHH", 3, 0, 1)
                sock.sendall(request[:3])
                sock.sendall(request[3:])
                response = sock.recv(64)
                self.assertEqual(response[:7], struct.pack(">HHHB", 7, 0, 5, 1))
                self.assertEqual(response[7:], b"\x03\x02" + struct.pack(">H", 6000))
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.sendall(struct.pack(">HHHB", 1, 1, 0, 1))
                sock.shutdown(socket.SHUT_WR)
            for _ in range(50):
                if "invalid-frame" in [event[1] for event in self.bus.events]:
                    break
                time.sleep(.01)
            self.assertIn("invalid-frame", [event[1] for event in self.bus.events])
        finally:
            decoy.stop()
            decoy.join(2)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.bus = FakeBus()
        self.profile = PROFILES["siemens_s7_1200"]

    def _exchange(self, decoy, request):
        decoy.start()
        decoy.ready.wait(2)
        self.assertTrue(decoy.bound)
        try:
            with socket.create_connection(("127.0.0.1", decoy.server.getsockname()[1]), timeout=2) as sock:
                sock.sendall(request)
                return sock.recv(1024)
        finally:
            decoy.stop()
            decoy.join(2)

    def test_s7_cotp_confirm(self):
        decoy = S7Decoy("127.0.0.1", 0, self.profile, self.bus)
        reply = self._exchange(decoy, bytes.fromhex("0300001611e00001000200c0010ac1020102c2020102"))
        self.assertEqual(reply, S7Decoy.CONNECTION_CONFIRM)

    def test_iec104_startdt(self):
        decoy = IEC104Decoy("127.0.0.1", 0, self.profile, self.bus)
        self.assertEqual(self._exchange(decoy, b"\x68\x04\x07\x00\x00\x00"),
                         b"\x68\x04\x0b\x00\x00\x00")

    def test_enip_register_session_header(self):
        decoy = EtherNetIPDecoy("127.0.0.1", 0, self.profile, self.bus)
        request = struct.pack("<HHII8sI", 0x65, 4, 0, 0, b"context!", 0) + b"\x01\x00\x00\x00"
        reply = self._exchange(decoy, request)
        self.assertEqual(len(reply), 28)
        self.assertEqual(struct.unpack("<HHI", reply[:8]), (0x65, 4, 1))


class EventAndConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cfg = dict(DEFAULT_CONFIG)
        for name in ("log", "intel", "blocklist"):
            self.cfg[name] = str(Path(self.temp.name) / name)

    def tearDown(self):
        self.temp.cleanup()

    def test_event_mapping_and_protected_blocklist(self):
        self.cfg.update(response_mode="blocklist", block_threshold=8, never_block=["10.0.0.0/24"])
        bus = EventBus(self.cfg)
        try:
            bus.record("modbus", ("10.0.0.2", 123), "modify-param", "test")
            self.assertNotIn("10.0.0.2", bus.blocked)
            record = bus.record("modbus", ("192.0.2.2", 123), "modify-param", "test")
            self.assertIn("192.0.2.2", bus.blocked)
            self.assertEqual(record["technique"]["id"], "T0836")
            self.assertIsNone(bus.record("modbus", ("192.0.2.3", 123), "connect", "test")["technique"])
            self.assertEqual(bus.snapshot()["totals"]["events"], 3)
            self.assertEqual(len(Path(self.cfg["log"]).read_text().splitlines()), 3)
        finally:
            bus.close()

    def test_console_requires_token_and_does_not_enable_cors(self):
        bus = EventBus(self.cfg)
        console = Console(bus, "127.0.0.1", 0, "long-secret-token-123").start()
        try:
            url = "http://127.0.0.1:{}/api/stats".format(console.server.server_address[1])
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(url, timeout=2)
            self.assertEqual(caught.exception.code, 401)
            request = urllib.request.Request(url, headers={"Authorization": "Bearer long-secret-token-123"})
            with urllib.request.urlopen(request, timeout=2) as response:
                self.assertEqual(response.status, 200)
                self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))
                self.assertEqual(json.load(response)["totals"]["events"], 0)
        finally:
            console.close()
            bus.close()

    def test_remote_console_requires_token(self):
        cfg = dict(self.cfg, console_host="0.0.0.0", console_token="")
        with self.assertRaisesRegex(ValueError, "requires"):
            validate(cfg)

    def test_demo_binds_decoys_to_loopback(self):
        args = argparse.Namespace(config=None, profile=None, host=None,
                                  console_host=None, console_port=None, demo=True)
        cfg, offset = load_config(args)
        self.assertEqual(cfg["host"], "127.0.0.1")
        self.assertEqual(offset, 5000)


if __name__ == "__main__":
    unittest.main()
