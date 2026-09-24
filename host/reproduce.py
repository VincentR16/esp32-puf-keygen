#!/usr/bin/env python3
"""
reproduce.py - Simulate the boot of the board on the stored dumps.

Same order the firmware will follow:
  1. read the helper data and check its signature. If it fails: stop,
     no decoding at all (no success/failure oracle for an attacker)
  2. for every dump: take the masked cells, rebuild the key,
     compare its key id with the one saved at enrollment

--tamper flips one bit of W before the check, to show the rejection.

Usage:
    python3 host/reproduce.py
    python3 host/reproduce.py --tamper
"""

import argparse
import os
import sys

from cryptography.hazmat.primitives import serialization

import fuzzy
from enroll import PK_PATH, key_id
from helperdata import HelperData
from mask import to_bits

# The last byte of W sits right before the 64-byte signature.
SIG_OFFSET_FROM_END = 64 + 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--tamper", action="store_true",
                    help="flip one bit of the helper data before checking it")
    args = ap.parse_args()

    with open(os.path.join(args.data, "hd.bin"), "rb") as fh:
        blob = bytearray(fh.read())
    if args.tamper:
        blob[-SIG_OFFSET_FROM_END] ^= 0x01
        print("Tampered: one bit of W flipped.\n")

    hd = HelperData.from_bytes(bytes(blob))
    with open(PK_PATH, "rb") as fh:
        pk = serialization.load_pem_public_key(fh.read())

    # 1. signature first
    if not hd.verify(pk):
        sys.exit("Signature INVALID: helper data rejected, nothing decoded.")
    print(f"Signature OK. {hd.describe()}")

    with open(os.path.join(args.data, "key_id.txt")) as fh:
        expected = fh.read().strip()
    print(f"Expected key id: {expected}\n")

    # 2. rebuild the key from every dump
    cells, helper = hd.cells(), hd.helper_ints()
    names = sorted(f for f in os.listdir(args.data) if f.endswith(".bin")
                   and f != "hd.bin")
    ok = failed = wrong = 0
    for name in names:
        with open(os.path.join(args.data, name), "rb") as fh:
            dump = fh.read()
        if len(dump) != hd.region_bytes:
            print(f"  {name}  wrong size, skipped")
            continue
        bits = to_bits(dump)
        key, errs = fuzzy.reproduce([bits[i] for i in cells], helper)
        if key is None:
            status, failed = "DECODE FAILED", failed + 1
        elif key_id(key) == expected:
            status, ok = "ok", ok + 1
        else:
            status, wrong = "WRONG KEY", wrong + 1
        print(f"  {name}  errors per block {errs}  {status}")

    print(f"\n{ok} ok, {failed} failed, {wrong} wrong key, out of {len(names)} dumps")


if __name__ == "__main__":
    main()