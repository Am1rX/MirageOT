"""Send one Modbus write to the local MirageOT demo and verify its response."""

import socket
import struct


REQUEST = struct.pack(">HHHBBHH", 1, 0, 6, 1, 5, 0, 0xFF00)


def main():
    with socket.create_connection(("127.0.0.1", 5502), timeout=3) as connection:
        connection.sendall(REQUEST)
        response = connection.recv(64)
    if response != REQUEST:
        raise SystemExit("unexpected Modbus response: {!r}".format(response))
    print("Modbus demo write acknowledged: {!r}".format(response))


if __name__ == "__main__":
    main()
