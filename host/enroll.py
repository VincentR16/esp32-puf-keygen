#!/usr/bin/env python3
"""
enroll.py - Enrollment on the Mac (trusted environment).

Builds the mask from the first 40 dumps, takes w from the stable cells,
runs the fuzzy extractor and saves the public helper data.

The key is never printed or saved. Only a key id (the first bytes of
SHA-256 of the key) is stored, to check the reconstruction in the tests.

Helper data must be generated once: the script refuses to overwrite it
unless --force is given.

Usage:
    python3 host/enroll.py --label enr
"""

import argparse
import hashlib
import json
import os

import fuzzy
from mask import TRAIN, build_mask, load, to_bits


def key_id(key):
    """Short fingerprint of the key, safe to show: it does not reveal the key."""
    return hashlib.sha256(key).hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="enr")
    ap.add_argument("--data", default="data")
    ap.add_argument("--force", action="store_true",
                    help="overwrite existing helper data")
    args = ap.parse_args()

    helper_path = os.path.join(args.data, "helper.json")
    keyid_path = os.path.join(args.data, "key_id.txt")
    if os.path.exists(helper_path) and not args.force:
        print(f"{helper_path} already exists. Helper data is generated once:")
        print("use --force only if you are sure.")
        return

    _, raw = load(args.data, args.label)
    if len(raw) < TRAIN:
        print(f"Need at least {TRAIN} dumps, found {len(raw)}.")
        return
    train = [to_bits(d) for d in raw[:TRAIN]]

    cells, golden, n_stable = build_mask(train)
    helper, key = fuzzy.generate(golden)

    bitmap = [0] * len(train[0])
    for i in cells:
        bitmap[i] = 1

    helper_data = {
        "version": 1,
        "region_bits": len(train[0]),
        "bch": {"n": fuzzy.N, "k": fuzzy.K, "t": fuzzy.T, "blocks": fuzzy.BLOCKS},
        "mask": fuzzy.pack_bits(bitmap).hex(),
        "W": [format(h, "064x") for h in helper],
    }
    with open(helper_path, "w") as fh:
        json.dump(helper_data, fh, indent=2)
    with open(keyid_path, "w") as fh:
        fh.write(key_id(key) + "\n")

    print(f"Stable cells: {n_stable}, used: {len(cells)}")
    print(f"Helper data:  {helper_path}")
    print(f"Key id:       {key_id(key)}")


if __name__ == "__main__":
    main()