#!/usr/bin/env python3
"""
enroll.py - Enrollment on the Mac (trusted environment). Run once.

Builds the mask from the first 40 dumps, takes w from the stable cells,
runs the fuzzy extractor and writes the signed helper data.

The signing key is created on the first run, together with the C header
holding the public key. Rebuild the firmware after that: the board needs
the public key to check the signature before using the helper data.

The PUF key is never printed or saved: only a key id (a fingerprint that
does not reveal it) so the reconstruction can be checked.

Usage:
    python3 host/enroll.py --mac d4:e9:f4:ed:8c:00 --addr 0x3FFB2C1C
"""

import argparse
import hashlib
import os

import fuzzy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from helperdata import HelperData
from mask import TRAIN, build_mask, load, to_bits

SK_PATH = "keys/sk_prov.pem"
PK_PATH = "keys/pk_prov.pem"
HEADER = "main/pk_prov.h"


def key_id(key):
    """Fingerprint of the PUF key: safe to show, does not reveal the key."""
    return hashlib.sha256(key).hexdigest()[:16]


def signing_key():
    """Load the signing key, or create it and write the C header."""
    if os.path.exists(SK_PATH):
        with open(SK_PATH, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)

    sk = ec.generate_private_key(ec.SECP256R1())
    os.makedirs(os.path.dirname(SK_PATH), exist_ok=True)
    with open(SK_PATH, "wb") as fh:
        fh.write(sk.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    os.chmod(SK_PATH, 0o600)
    with open(PK_PATH, "wb") as fh:
        fh.write(sk.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))

    # Uncompressed point, 0x04 || X || Y: the format the PSA crypto API wants.
    raw = sk.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)
    body = "\n".join("    " + ", ".join(f"0x{b:02X}" for b in raw[i:i + 8]) + ","
                     for i in range(0, len(raw), 8)).rstrip(",")
    os.makedirs(os.path.dirname(HEADER), exist_ok=True)
    with open(HEADER, "w") as fh:
        fh.write("/* Provisioner public key, written by host/enroll.py.\n"
                 " * Not a secret: it can verify a signature, not create one. */\n"
                 "#pragma once\n#include <stdint.h>\n\n"
                 f"static const uint8_t PK_PROV[{len(raw)}] = {{\n{body}\n}};\n")
    print(f"New signing key: {SK_PATH} (keep it out of git)")
    print(f"Public key:      {HEADER} -> rebuild the firmware")
    return sk


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mac", required=True, help="chip MAC, e.g. d4:e9:f4:ed:8c:00")
    ap.add_argument("--addr", required=True, help="SRAM region address, e.g. 0x3FFB2C1C")
    ap.add_argument("--label", default="enr")
    ap.add_argument("--data", default="data")
    ap.add_argument("--force", action="store_true",
                    help="overwrite existing helper data")
    args = ap.parse_args()

    hd_path = os.path.join(args.data, "hd.bin")
    if os.path.exists(hd_path) and not args.force:
        print(f"{hd_path} already exists. Helper data is generated once:")
        print("use --force only if you are sure.")
        return

    mac = bytes.fromhex(args.mac.replace(":", ""))
    if len(mac) != 6:
        print("The MAC must be 6 bytes.")
        return

    _, raw = load(args.data, args.label)
    if len(raw) < TRAIN:
        print(f"Need at least {TRAIN} dumps, found {len(raw)}.")
        return
    if len({len(d) for d in raw}) != 1:
        print("The dumps do not all have the same size.")
        return

    train = [to_bits(d) for d in raw[:TRAIN]]
    cells, golden, n_stable = build_mask(train)
    helper, key = fuzzy.generate(golden)

    hd = HelperData.build(mac=mac, region_addr=int(args.addr, 16),
                          region_bits=len(train[0]),
                          cells=cells, helper_ints=helper)
    hd.sign(signing_key())

    with open(hd_path, "wb") as fh:
        fh.write(hd.to_bytes())
    with open(os.path.join(args.data, "key_id.txt"), "w") as fh:
        fh.write(key_id(key) + "\n")

    print(f"Stable cells: {n_stable}, used: {len(cells)}")
    print(f"Helper data:  {hd_path} ({len(hd.to_bytes())} bytes)")
    print(f"              {hd.describe()}")
    print(f"Key id:       {key_id(key)}")


if __name__ == "__main__":
    main()