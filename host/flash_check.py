#!/usr/bin/env python3
"""
flash_check.py - Look for the keys in a full dump of the ESP32 flash.

The claim of the project: no secret is stored in non-volatile memory,
the key is rebuilt from the silicon at every power-up. This script
checks it on a real dump, read as an attacker with a USB cable would:

    python -m esptool --port /dev/cu.usbserial-0001 read-flash 0 ALL flash_dump.bin
    python3 host/flash_check.py flash_dump.bin

SECRETS (must NOT be found): K_master, K_auth, K_enc, as raw bytes and
as hex text. K_master is rebuilt on the Mac from an enrollment dump,
K_auth and K_enc come from keys/server_keys.json.

CONTROLS (must be found): things that are in the flash on purpose. They
prove the search works on this dump, so "not found" means something.
  - the helper data: public by design, protected by its signature
  - the WiFi password: compiled into the firmware from wifi_secrets.h,
    i.e. a secret stored the classic way, readable with one command

The dump contains the WiFi password: delete it after the demo and
never commit it.

Needs the project venv (it reuses server_keys.py).
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helperdata import HelperData  # noqa: E402
from server_keys import rebuild_master  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
HD_PATH = ROOT / "data" / "fixed" / "hd.bin"
KID_PATH = ROOT / "data" / "fixed" / "key_id.txt"
DUMPS = ROOT / "data" / "fixed"
KEYS = ROOT / "keys" / "server_keys.json"
SECRETS_H = ROOT / "main" / "wifi_secrets.h"


def find_all(blob, needle):
    """Offsets of every occurrence of needle in blob."""
    out, i = [], blob.find(needle)
    while i != -1:
        out.append(i)
        i = blob.find(needle, i + 1)
    return out


def forms(value):
    """The ways a key could sit in flash: raw bytes, hex text."""
    return {
        "raw": value,
        "hex": value.hex().encode(),
        "HEX": value.hex().upper().encode(),
    }


def search(dump, name, value):
    """-> list of (form, offsets) where value was found."""
    hits = []
    for form, needle in forms(value).items():
        offsets = find_all(dump, needle)
        if offsets:
            hits.append((form, offsets))
    return hits


def where(hits):
    return ", ".join(f"{form} @ " + " ".join(f"0x{o:06x}" for o in offs[:3])
                     for form, offs in hits)


def wifi_password():
    m = re.search(r'#define\s+WIFI_PASSWORD\s+"([^"]*)"', SECRETS_H.read_text())
    return m.group(1).encode() if m else None


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    dump = Path(sys.argv[1]).read_bytes()
    print(f"flash dump: {len(dump)} bytes ({len(dump) // 1024} KiB)\n")

    # --- the secrets ---
    hd_bytes = HD_PATH.read_bytes()
    hd = HelperData.from_bytes(hd_bytes)
    expected = KID_PATH.read_text().strip().lower()
    k_master = rebuild_master(hd, DUMPS, expected)
    rec = json.loads(KEYS.read_text())
    secrets = {
        "K_master": k_master,
        "K_auth": bytes.fromhex(rec["k_auth"]),
        "K_enc": bytes.fromhex(rec["k_enc"]),
    }

    print("\nSECRETS (must NOT be in the flash)")
    clean = True
    for name, value in secrets.items():
        hits = search(dump, name, value)
        if hits:
            clean = False
            print(f"  {name:<10} FOUND  {where(hits)}")
        else:
            print(f"  {name:<10} not found")

    # --- the controls ---
    print("\nCONTROLS (must be in the flash: they prove the search works)")
    controls = {
        "helper data (first 64 B)": hd_bytes[:64],
        "helper data signature": hd_bytes[-64:],
    }
    pw = wifi_password()
    if pw:
        controls["WiFi password"] = pw
    controls_ok = True
    for name, value in controls.items():
        offsets = find_all(dump, value)
        if offsets:
            print(f"  {name:<26} found  @ 0x{offsets[0]:06x}")
        else:
            controls_ok = False
            print(f"  {name:<26} NOT found")

    print()
    if not controls_ok:
        print("A control is missing: is this a dump of the right board, "
              "with the current firmware?")
    elif clean:
        print("RESULT: no key in the flash. The helper data and the WiFi "
              "password are readable;\nthe PUF keys exist only in RAM, "
              "rebuilt from the SRAM at every power-up.")
    else:
        print("RESULT: a key IS stored in the flash: the claim does not hold.")


if __name__ == "__main__":
    main()