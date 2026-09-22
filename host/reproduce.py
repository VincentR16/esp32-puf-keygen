#!/usr/bin/env python3
"""
reproduce.py - Simulate the boot-time reconstruction on stored dumps.

For every dump in data/: take the cells selected by the mask, run the
fuzzy extractor reconstruction and compare the key id with the one
saved at enrollment. Every dump should give the same key.

Usage:
    python3 host/reproduce.py
"""

import argparse
import json
import os

import fuzzy
from enroll import key_id
from mask import to_bits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    args = ap.parse_args()

    with open(os.path.join(args.data, "helper.json")) as fh:
        hd = json.load(fh)
    with open(os.path.join(args.data, "key_id.txt")) as fh:
        expected = fh.read().strip()

    mask_bits = to_bits(bytes.fromhex(hd["mask"]))
    cells = [i for i, b in enumerate(mask_bits) if b]
    helper = [int(h, 16) for h in hd["W"]]

    names = sorted(f for f in os.listdir(args.data) if f.endswith(".bin"))
    ok = failed = wrong = 0
    print(f"Expected key id: {expected}\n")
    for name in names:
        with open(os.path.join(args.data, name), "rb") as fh:
            bits = to_bits(fh.read())
        w_noisy = [bits[i] for i in cells]
        key, errs = fuzzy.reproduce(w_noisy, helper)
        if key is None:
            status = "DECODE FAILED"
            failed += 1
        elif key_id(key) == expected:
            status = "ok"
            ok += 1
        else:
            status = "WRONG KEY"
            wrong += 1
        print(f"  {name}  errors per block {errs}  {status}")

    print(f"\n{ok} ok, {failed} failed, {wrong} wrong key, out of {len(names)} dumps")


if __name__ == "__main__":
    main()