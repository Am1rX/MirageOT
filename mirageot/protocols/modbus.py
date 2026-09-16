"""Bounded, stateful Modbus/TCP decoy with protocol exception responses."""

import struct
import threading

from .base import TCPDecoy


class ModbusDecoy(TCPDecoy):
    protocol = "modbus"

    def __init__(self, host, port, profile, bus):
        super().__init__(host, port, profile, bus)
        self.lock = threading.Lock()
        self.coils = [False] * 128
        self.discrete = [False] * 128
        self.input_regs = [4720, 6130, 890, 320, 4150] + [0] * 123
        self.holding = [6000, 5500, 7000, 1000, 8500] + [0] * 123
        critical = bus.cfg.get("critical_points", {})
        self.critical_coils = set(critical.get("coil", []))
        self.critical_holding = set(critical.get("holding", []))

    def handle(self, conn, addr):
        while not self.stop_event.is_set():
            header = self.recvn(conn, 7)
            if header is None:
                return
            transaction, protocol, length, unit = struct.unpack(">HHHB", header)
            if protocol != 0 or not 2 <= length <= 254:
                self.bus.record(self.protocol, addr, "invalid-frame", "invalid MBAP protocol or length")
                return
            pdu = self.recvn(conn, length - 1)
            if pdu is None:
                return
            response = self.process_pdu(addr, unit, pdu)
            conn.sendall(struct.pack(">HHHB", transaction, 0, len(response) + 1, unit) + response)

    @staticmethod
    def exception(function, code):
        return bytes((function | 0x80, code))

    def process_pdu(self, addr, unit, pdu):
        function = pdu[0]
        if function in (1, 2, 3, 4):
            if len(pdu) != 5:
                return self.exception(function, 3)
            start, count = struct.unpack(">HH", pdu[1:])
            max_count = 2000 if function in (1, 2) else 125
            if count < 1 or count > max_count:
                return self.exception(function, 3)
            bank = {1: self.coils, 2: self.discrete, 3: self.holding, 4: self.input_regs}[function]
            if start + count > len(bank):
                return self.exception(function, 2)
            with self.lock:
                values = bank[start:start + count]
            self.bus.record(self.protocol, addr, "read", "fn={} start={} count={} unit={}".format(function, start, count, unit))
            if function in (1, 2):
                payload = bytearray((count + 7) // 8)
                for index, value in enumerate(values):
                    if value:
                        payload[index // 8] |= 1 << (index % 8)
                return bytes((function, len(payload))) + payload
            return bytes((function, count * 2)) + struct.pack(">{}H".format(count), *values)

        if function in (5, 6):
            if len(pdu) != 5:
                return self.exception(function, 3)
            start, value = struct.unpack(">HH", pdu[1:])
            if start >= 128:
                return self.exception(function, 2)
            if function == 5 and value not in (0x0000, 0xFF00):
                return self.exception(function, 3)
            with self.lock:
                if function == 5:
                    self.coils[start] = value == 0xFF00
                else:
                    self.holding[start] = value
            self._write_event(addr, function, start, 1, unit)
            return pdu

        if function in (15, 16):
            if len(pdu) < 6:
                return self.exception(function, 3)
            start, count, byte_count = struct.unpack(">HHB", pdu[1:6])
            max_count = 1968 if function == 15 else 123
            expected = (count + 7) // 8 if function == 15 else count * 2
            if not 1 <= count <= max_count or byte_count != expected or len(pdu) != 6 + expected:
                return self.exception(function, 3)
            if start + count > 128:
                return self.exception(function, 2)
            with self.lock:
                if function == 15:
                    values = pdu[6:]
                    for index in range(count):
                        self.coils[start + index] = bool(values[index // 8] & (1 << (index % 8)))
                else:
                    values = struct.unpack(">{}H".format(count), pdu[6:])
                    self.holding[start:start + count] = values
            self._write_event(addr, function, start, count, unit)
            return struct.pack(">BHH", function, start, count)

        self.bus.record(self.protocol, addr, "discover", "unsupported function 0x{:02x}".format(function))
        return self.exception(function, 1)

    def _write_event(self, addr, function, start, count, unit):
        points = self.critical_coils if function in (5, 15) else self.critical_holding
        if any(start <= point < start + count for point in points):
            action = "critical-write-attempt"
        else:
            action = "manipulate" if function in (5, 15) else "modify-param"
        self.bus.record(self.protocol, addr, action,
                        "fn={} start={} count={} unit={} (decoy state only)".format(function, start, count, unit))
