#!/usr/bin/env python3
"""
server.py - Line-based TCP server for the PUF device (step 4).

Mutual authentication with K_auth (from keys/server_keys.json):
    device -> server   HELLO  <id>
    server -> device   NONCE  <N_s>
    device -> server   AUTH   <N_d> <tag_d>   tag_d = HMAC(K_auth, "dev"||N_s||N_d||id)
    server -> device   SERVER <tag_s>         tag_s = HMAC(K_auth, "srv"||N_s||N_d||id)
On any failure the server answers DENIED and closes the connection.
After a successful handshake every further line is printed.

Standard library only.

Usage:
    python3 host/server.py
    python3 host/server.py --wrong-key     # negative test: one bit of K_auth flipped
"""

import argparse
import hashlib
import hmac
import json
import os
import socketserver
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys" / "server_keys.json"

NONCE_LEN = 16
ID_LEN = 6
TAG_LEN = 32

# Filled in main(): the one registered device.
DEVICE_ID = b""
K_AUTH = b""


def auth_tag(role, ns, nd, dev_id):
    """HMAC(K_auth, role || N_s || N_d || id), fixed-length fields."""
    return hmac.new(K_AUTH, role + ns + nd + dev_id, hashlib.sha256).digest()


def unhex(text, length):
    """Exactly `length` bytes of hex, or None."""
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return None
    return raw if len(raw) == length else None


class Device(socketserver.StreamRequestHandler):
    def handle(self):
        self.peer = f"{self.client_address[0]}:{self.client_address[1]}"
        self.log("connected")
        if self.authenticate():
            for raw in self.rfile:                  # after the handshake
                self.log(f"<- {raw.decode(errors='replace').rstrip()}")
        self.log("closed")

    def authenticate(self):
        # 1. HELLO <id>
        parts = self.recv().split()
        if len(parts) != 2 or parts[0] != "HELLO":
            return self.deny("expected HELLO")
        dev_id = unhex(parts[1], ID_LEN)
        if dev_id is None or dev_id != DEVICE_ID:
            return self.deny("unknown device id")

        # 2. NONCE <N_s>: fresh for every connection
        ns = os.urandom(NONCE_LEN)
        self.send(f"NONCE {ns.hex()}")

        # 3. AUTH <N_d> <tag_d>
        parts = self.recv().split()
        if len(parts) != 3 or parts[0] != "AUTH":
            return self.deny("expected AUTH")
        nd, tag_d = unhex(parts[1], NONCE_LEN), unhex(parts[2], TAG_LEN)
        if nd is None or tag_d is None:
            return self.deny("malformed AUTH")
        # compare_digest: constant time, no byte-by-byte guessing
        if not hmac.compare_digest(tag_d, auth_tag(b"dev", ns, nd, dev_id)):
            return self.deny("device tag INVALID")

        # 4. SERVER <tag_s>: prove we know K_auth too
        self.send(f"SERVER {auth_tag(b'srv', ns, nd, dev_id).hex()}")
        self.log("device AUTHENTICATED")
        return True

    def deny(self, why):
        self.log(f"DENIED: {why}")
        self.send("DENIED")
        return False

    def recv(self):
        line = self.rfile.readline().decode(errors="replace").rstrip("\r\n")
        self.log(f"<- {line}")
        return line

    def send(self, line):
        self.wfile.write((line + "\n").encode())
        self.log(f"-> {line}")

    def log(self, msg):
        print(f"[{self.peer}] {msg}")


class Server(socketserver.TCPServer):
    allow_reuse_address = True                      # quick restarts


def main():
    global DEVICE_ID, K_AUTH
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--keys", type=Path, default=KEYS)
    ap.add_argument("--wrong-key", action="store_true",
                    help="flip one bit of K_auth: the device must be DENIED")
    args = ap.parse_args()

    rec = json.loads(args.keys.read_text())
    DEVICE_ID = bytes.fromhex(rec["device_id"])
    K_AUTH = bytes.fromhex(rec["k_auth"])
    if args.wrong_key:
        K_AUTH = bytes([K_AUTH[0] ^ 0x01]) + K_AUTH[1:]
        print("NEGATIVE TEST: K_auth has one bit flipped")

    print(f"device {DEVICE_ID.hex()}, key id {rec['key_id']}")
    with Server(("0.0.0.0", args.port), Device) as srv:
        print(f"listening on port {args.port}, Ctrl+C to stop")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print()


if __name__ == "__main__":
    main()