#!/usr/bin/env python3
"""
check_wprime.py - Check the C extraction of w' (step 3a) against fuzzy.py.

The debug firmware prints, at every boot:
    WPRIME <256 hex chars>     w' as extracted in C
    KEYID  <16 hex chars>      key id of SHA-256(w'), computed in C, no BCH

For every boot this script:
  1. decodes w' with the Python reference (fuzzy.reproduce) and the W of
     data/fixed/hd.bin, and compares the key id with data/fixed/key_id.txt.
     If the C extraction were wrong (bit order, offsets) w' would be
     ~50% wrong and decoding would fail: a match proves the extraction.
  2. recomputes the raw key id of w' and compares it with the KEYID line
     printed by the board: a match proves the C SHA-256 and packing.

Usage (log copied from idf.py monitor, one or more boots):
    python3 host/check_wprime.py boot.log
    python3 host/check_wprime.py < boot.log
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fuzzy  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
HD_PATH = ROOT / "data" / "fixed" / "hd.bin"
KID_PATH = ROOT / "data" / "fixed" / "key_id.txt"

HD_W = 1045                         # offset of W in the helper data
W_LEN = 128                         # bytes of W (and of packed w')
NBITS = fuzzy.N * fuzzy.BLOCKS      # 1020


def unpack(buf, n):
    """Bytes -> bit list, MSB first (same convention as fuzzy.pack_bits)."""
    return [(buf[i // 8] >> (7 - i % 8)) & 1 for i in range(n)]


def key_id(key):
    return hashlib.sha256(key).digest()[:8].hex()


def helper_blocks(hd):
    """W from the helper data -> 4 ints, bit i = coefficient of x^i."""
    wbits = unpack(hd[HD_W:HD_W + W_LEN], NBITS)
    return [fuzzy.bits_to_int(wbits[b * fuzzy.N:(b + 1) * fuzzy.N])
            for b in range(fuzzy.BLOCKS)]


def parse_log(lines):
    """-> list of (wprime_hex, keyid_hex or None), one per boot."""
    boots = []
    for line in lines:
        line = line.strip()
        if line.startswith("WPRIME "):
            boots.append([line.split()[1], None])
        elif line.startswith("KEYID ") and boots and boots[-1][1] is None:
            boots[-1][1] = line.split()[1]
    return boots


def main():
    text = open(sys.argv[1]).read() if len(sys.argv) > 1 else sys.stdin.read()
    boots = parse_log(text.splitlines())
    if not boots:
        sys.exit("no WPRIME line found: is PUF_DEBUG_DUMP set to 1?")

    helper = helper_blocks(HD_PATH.read_bytes())
    expected = KID_PATH.read_text().strip().lower()
    print(f"expected key id: {expected}\n")
    print(f"{'boot':>4}  {'errors per block':<18} {'BCH (Python)':<14} "
          f"{'raw C = raw Py':<15} raw = expected")

    for i, (wp_hex, kid_c) in enumerate(boots, 1):
        wp = bytes.fromhex(wp_hex)
        if len(wp) != W_LEN:
            print(f"{i:>4}  w' has {len(wp)} bytes, expected {W_LEN}")
            continue
        pad_ok = (wp[-1] & 0x0F) == 0     # the last 4 bits must be zero

        k, errs = fuzzy.reproduce(unpack(wp, NBITS), helper)
        if k is None:
            decoded = "FAIL"
        else:
            decoded = "ok" if key_id(k) == expected else "WRONG KEY"

        raw = key_id(hashlib.sha256(wp).digest())
        same_c = "-" if kid_c is None else ("yes" if kid_c == raw else "NO")
        raw_exp = "yes" if raw == expected else "no"

        err_str = " ".join("-" if e is None else str(e) for e in errs)
        note = "" if pad_ok else "   (padding bits not zero!)"
        print(f"{i:>4}  {err_str:<18} {decoded:<14} {same_c:<15} {raw_exp}{note}")


if __name__ == "__main__":
    main()