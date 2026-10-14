#!/usr/bin/env python3
"""
server_keys.py - Derive the server copy of K_auth and K_enc (step 3c).

The device never exports its keys, and enroll.py never saved them.
The server gets them here, on the Mac (trusted environment):
  1. check the helper data signature, as the firmware does
  2. rebuild K_master from a stored dump with fuzzy.reproduce and check
     its key id against data/fixed/key_id.txt
  3. K_auth = HKDF-Expand(K_master, "puf-auth-v1", 32)
     K_enc  = HKDF-Expand(K_master, "puf-enc-v1",  32)
  4. write them to keys/server_keys.json (keys/ is git-ignored), with
     the device id (its MAC, from the helper data)

Note: the stored dumps are equivalent to the key. After the server is
provisioned they should be deleted; they are kept during development.

Usage:
    python3 host/server_keys.py
    python3 host/server_keys.py --dumps data/fixed --out keys/server_keys.json
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fuzzy  # noqa: E402
from helperdata import HelperData  # noqa: E402
from mask import to_bits  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

LABEL_AUTH = b"puf-auth-v1"
LABEL_ENC = b"puf-enc-v1"


def key_id(key):
    """First 8 bytes of SHA-256(key), as in enroll.py and crypto.c."""
    return hashlib.sha256(key).digest()[:8].hex()


def hkdf_expand(prk, info):
    """HKDF-Expand(prk, info, 32). Extract is skipped: prk is uniform."""
    out = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info).derive(prk)
    # For 32 bytes, HKDF-Expand is a single block: HMAC(prk, info || 0x01).
    assert out == hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return out


def rebuild_master(hd, dumps_dir, expected):
    """K_master from the first stored dump that decodes to the enrolled key."""
    cells, helper = hd.cells(), hd.helper_ints()
    for name in sorted(os.listdir(dumps_dir)):
        path = dumps_dir / name
        if not name.endswith(".bin") or path.stat().st_size != hd.region_bytes:
            continue                    # skips hd.bin, nvs.bin, anything else
        bits = to_bits(path.read_bytes())
        k_master, errs = fuzzy.reproduce([bits[i] for i in cells], helper)
        if k_master is not None and key_id(k_master) == expected:
            print(f"K_master rebuilt from {name}, errors per block {errs}")
            return k_master
    sys.exit(f"no dump in {dumps_dir} rebuilds key id {expected}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hd", default=ROOT / "data" / "fixed" / "hd.bin", type=Path)
    ap.add_argument("--kid", default=ROOT / "data" / "fixed" / "key_id.txt", type=Path)
    ap.add_argument("--dumps", default=ROOT / "data" / "fixed", type=Path)
    ap.add_argument("--pk", default=ROOT / "keys" / "pk_prov.pem", type=Path)
    ap.add_argument("--out", default=ROOT / "keys" / "server_keys.json", type=Path)
    args = ap.parse_args()

    # 1. signature first, as on the device
    hd_bytes = args.hd.read_bytes()
    hd = HelperData.from_bytes(hd_bytes)
    pk = serialization.load_pem_public_key(args.pk.read_bytes())
    if not hd.verify(pk):
        sys.exit("Signature INVALID: helper data rejected.")
    print("Signature OK")

    # 2. K_master
    expected = args.kid.read_text().strip().lower()
    k_master = rebuild_master(hd, args.dumps, expected)

    # 3. derived keys
    k_auth = hkdf_expand(k_master, LABEL_AUTH)
    k_enc = hkdf_expand(k_master, LABEL_ENC)

    # 4. server key file, readable by the owner only
    args.out.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "device_id": hd_bytes[5:11].hex(),     # MAC, offset 5 of the helper data
        "key_id": expected,
        "k_auth": k_auth.hex(),
        "k_enc": k_enc.hex(),
        "label_auth": LABEL_AUTH.decode(),
        "label_enc": LABEL_ENC.decode(),
    }
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(record, fh, indent=2)

    print(f"KEYID    {expected}")
    print(f"server keys written to {args.out}")


if __name__ == "__main__":
    main()