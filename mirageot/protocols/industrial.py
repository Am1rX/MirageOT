"""Framed industrial protocol decoys.

S7, DNP3, and BACnet listeners are deliberately narrow sensors. They log
well-formed probes and never claim to be full protocol implementations.
"""

import struct

from .base import TCPDecoy, UDPDecoy


class S7Decoy(TCPDecoy):
    protocol = "s7comm"
    CONNECTION_CONFIRM = bytes.fromhex("0300001611d00001000200c0010ac1020102c2020102")

    def handle(self, conn, addr):
        while not self.stop_event.is_set():
            header = self.recvn(conn, 4)
            if header is None:
                return
            if header[:2] != b"\x03\x00":
                raise ValueError("invalid TPKT version")
            length = struct.unpack(">H", header[2:])[0]
            if not 7 <= length <= 2048:
                raise ValueError("invalid TPKT length")
            payload = self.recvn(conn, length - 4)
            if payload is None:
                return
            if len(payload) < 3:
                raise ValueError("short COTP frame")
            if payload[1] == 0xE0:
                self.bus.record(self.protocol, addr, "discover", "COTP connection request")
                conn.sendall(self.CONNECTION_CONFIRM)
            elif payload[1] == 0xF0 and len(payload) >= 4 and payload[3] == 0x32:
                self.bus.record(self.protocol, addr, "sysinfo", "S7 communication job")
                # A false S7 response would misrepresent protocol support.
            else:
                self.bus.record(self.protocol, addr, "discover", "other COTP frame")


class DNP3Decoy(TCPDecoy):
    protocol = "dnp3"

    def handle(self, conn, addr):
        while not self.stop_event.is_set():
            header = self.recvn(conn, 3)
            if header is None:
                return
            if header[:2] != b"\x05\x64" or not 5 <= header[2] <= 250:
                raise ValueError("invalid DNP3 start or length")
            # The link header is fixed size. Data blocks and CRC are intentionally
            # not emulated; consume only the header and close to avoid desync.
            link = self.recvn(conn, 7)
            if link is None:
                return
            control = link[0]
            self.bus.record(self.protocol, addr, "discover", "DNP3 link probe control=0x{:02x}".format(control))
            return


class IEC104Decoy(TCPDecoy):
    protocol = "iec104"

    def handle(self, conn, addr):
        while not self.stop_event.is_set():
            header = self.recvn(conn, 2)
            if header is None:
                return
            if header[0] != 0x68 or not 4 <= header[1] <= 253:
                raise ValueError("invalid IEC-104 APCI")
            payload = self.recvn(conn, header[1])
            if payload is None:
                return
            control = payload[:4]
            if control == b"\x07\x00\x00\x00":
                conn.sendall(b"\x68\x04\x0b\x00\x00\x00")
                action = "discover"
                detail = "STARTDT activation"
            elif control == b"\x13\x00\x00\x00":
                conn.sendall(b"\x68\x04\x23\x00\x00\x00")
                action, detail = "discover", "STOPDT activation"
            elif control == b"\x43\x00\x00\x00":
                conn.sendall(b"\x68\x04\x83\x00\x00\x00")
                action, detail = "discover", "TESTFR activation"
            else:
                action, detail = "read", "IEC-104 I/S frame"
            self.bus.record(self.protocol, addr, action, detail)


class EtherNetIPDecoy(TCPDecoy):
    protocol = "ethernetip"

    def handle(self, conn, addr):
        while not self.stop_event.is_set():
            header = self.recvn(conn, 24)
            if header is None:
                return
            command, length, session, status, context, options = struct.unpack("<HHII8sI", header)
            if length > 1024:
                raise ValueError("oversized EtherNet/IP payload")
            payload = self.recvn(conn, length) if length else b""
            if payload is None:
                return
            if command == 0x65 and payload == b"\x01\x00\x00\x00":
                self.bus.record(self.protocol, addr, "discover", "RegisterSession")
                result = struct.pack("<HHII8sI", command, 4, 1, 0, context, 0) + payload
                conn.sendall(result)
            elif command == 0x63 and length == 0:
                self.bus.record(self.protocol, addr, "sysinfo", "ListIdentity")
                name = self.profile["product"].encode("ascii", "replace")[:32]
                identity = (struct.pack("<HH", 1, 0x000C) + b"\x00" * 16 +
                            struct.pack("<HHHBBH", 1, 14, 1, 1, 0, 0) +
                            struct.pack("<I", 12345) + bytes((len(name),)) + name + b"\x00")
                items = struct.pack("<H", 1) + struct.pack("<HH", 0x000C, len(identity)) + identity
                conn.sendall(struct.pack("<HHII8sI", command, len(items), session, 0, context, 0) + items)
            else:
                self.bus.record(self.protocol, addr, "discover", "ENIP command 0x{:04x}".format(command))


class SNMPDecoy(UDPDecoy):
    protocol = "snmp"

    def handle(self, server, data, addr):
        if len(data) < 4 or data[0] != 0x30:
            raise ValueError("invalid SNMP BER sequence")
        self.bus.record(self.protocol, addr, "sysinfo", "SNMP BER probe")


class BACnetDecoy(UDPDecoy):
    protocol = "bacnet"

    def handle(self, server, data, addr):
        if len(data) < 4 or data[0] != 0x81 or struct.unpack(">H", data[2:4])[0] != len(data):
            raise ValueError("invalid BACnet BVLC length")
        self.bus.record(self.protocol, addr, "discover", "BACnet BVLC probe")
