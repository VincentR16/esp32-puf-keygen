#!/usr/bin/env python3
"""
server.py - TCP server for the PUF device (step 4).

1. Mutual authentication with K_auth (keys/server_keys.json):
    device -> server   HELLO  <id>
    server -> device   NONCE  <N_s>
    device -> server   AUTH   <N_d> <tag_d>   tag_d = HMAC(K_auth, "dev"||N_s||N_d||id)
    server -> device   SERVER <tag_s>         tag_s = HMAC(K_auth, "srv"||N_s||N_d||id)
   On any failure the server answers DENIED and closes the connection.

2. Encrypted data with a session key:
    K_sess = HKDF-Expand(K_enc, "puf-sess-v1" || N_s || N_d, 32)
    device -> server   DATA <seq> <ciphertext || tag>
   AES-256-GCM, nonce = 0^8 || seq, AD = "data" || id || seq.
   The tag is checked first, then seq must be strictly increasing (replay).

Needs the `cryptography` package (AES-GCM): run it with the project venv.

Usage:
    python3 host/server.py
"""

import argparse
import hashlib
import hmac
import json
import os
import socketserver
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys" / "server_keys.json"

NONCE_LEN = 16
ID_LEN = 6
TAG_LEN = 32
SESS_LABEL = b"puf-sess-v1"

# Filled in main(): the one registered device.
DEVICE_ID = b""
K_AUTH = b""
K_ENC = b""


def auth_tag(role, ns, nd, dev_id):
    """HMAC(K_auth, role || N_s || N_d || id), fixed-length fields."""
    return hmac.new(K_AUTH, role + ns + nd + dev_id, hashlib.sha256).digest()


def session_key(ns, nd):
    """HKDF-Expand(K_enc, "puf-sess-v1" || N_s || N_d, 32) = one HMAC block."""
    info = SESS_LABEL + ns + nd
    return hmac.new(K_ENC, info + b"\x01", hashlib.sha256).digest()


def unhex(text, length=None):
    """Bytes from hex (of the given length, if any), or None."""
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return None
    return raw if length is None or len(raw) == length else None


class Device(socketserver.StreamRequestHandler):
    def handle(self):
        self.peer = f"{self.client_address[0]}:{self.client_address[1]}"
        self.log("connected")
        session = self.authenticate()
        if session:
            self.receive_data(*session)
        self.log("closed")

    # ---------- 1. authentication ----------

    def authenticate(self):
        """-> (dev_id, K_sess) on success, None after sending DENIED."""
        parts = self.recv().split()
        if len(parts) != 2 or parts[0] != "HELLO":
            return self.deny("expected HELLO")
        dev_id = unhex(parts[1], ID_LEN)
        if dev_id is None or dev_id != DEVICE_ID:
            return self.deny("unknown device id")

        ns = os.urandom(NONCE_LEN)                  # fresh for every connection
        self.send(f"NONCE {ns.hex()}")

        parts = self.recv().split()
        if len(parts) != 3 or parts[0] != "AUTH":
            return self.deny("expected AUTH")
        nd, tag_d = unhex(parts[1], NONCE_LEN), unhex(parts[2], TAG_LEN)
        if nd is None or tag_d is None:
            return self.deny("malformed AUTH")
        if not hmac.compare_digest(tag_d, auth_tag(b"dev", ns, nd, dev_id)):
            return self.deny("device tag INVALID")

        self.send(f"SERVER {auth_tag(b'srv', ns, nd, dev_id).hex()}")
        self.log("device AUTHENTICATED")
        return dev_id, session_key(ns, nd)

    def deny(self, why):
        self.log(f"DENIED: {why}")
        self.send("DENIED")
        return None

    # ---------- 2. encrypted data ----------

    def receive_data(self, dev_id, k_sess):
        gcm = AESGCM(k_sess)
        self.last_seq = 0
        for raw in self.rfile:
            line = raw.decode(errors="replace").rstrip("\r\n")
            self.log(f"<- {line}")
            self.open_data(gcm, dev_id, line)

    def open_data(self, gcm, dev_id, line):
        """Check and decrypt one DATA line. Returns True if accepted."""
        parts = line.split()
        if len(parts) != 3 or parts[0] != "DATA" or len(parts[1]) != 8:
            self.log(f"REJECTED: malformed DATA")
            return False
        seq, ct = int(parts[1], 16), unhex(parts[2])
        if ct is None:
            self.log(f"REJECTED: malformed DATA")
            return False

        seq_b = seq.to_bytes(4, "big")
        nonce = bytes(8) + seq_b
        ad = b"data" + dev_id + seq_b
        try:
            pt = gcm.decrypt(nonce, ct, ad)         # checks the tag first
        except InvalidTag:
            self.log(f"REJECTED: bad tag (modified or wrong key)")
            return False
        if seq <= self.last_seq:                    # authentic but old: replay
            self.log(f"REJECTED: seq {seq} not after {self.last_seq} (replay)")
            return False

        self.last_seq = seq
        temp, hum = pt.decode().split(",")
        self.log(f"seq {seq}: temperature {temp} C, humidity {hum} %")
        return True

    # ---------- line I/O ----------

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
    global DEVICE_ID, K_AUTH, K_ENC
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--keys", type=Path, default=KEYS)
    args = ap.parse_args()

    rec = json.loads(args.keys.read_text())
    DEVICE_ID = bytes.fromhex(rec["device_id"])
    K_AUTH = bytes.fromhex(rec["k_auth"])
    K_ENC = bytes.fromhex(rec["k_enc"])

    print(f"device {DEVICE_ID.hex()}, key id {rec['key_id']}")
    with Server(("0.0.0.0", args.port), Device) as srv:
        print(f"listening on port {args.port}, Ctrl+C to stop")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print()


if __name__ == "__main__":
    main()