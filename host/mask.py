#!/usr/bin/env python3
"""
mask.py - Build the stable-cell mask and measure the residual error.

The first 40 dumps build the mask: a cell is stable if it has the same
value in all of them. The key uses the first 1020 stable cells, that is
4 blocks of BCH(255, 179, t=10). The remaining dumps are used only to
check how many of those cells still flip.

Usage:
    python host/mask.py --label enr
"""

import argparse
import os

N_BLOCK = 255                   # BCH block length
N_BLOCKS = 4                    # BCH(255, 179, 10) x 4
T = 10                          # errors correctable per block
N_CELLS = N_BLOCK * N_BLOCKS    # 1020 cells used for the key
TRAIN = 40                      # dumps used to build the mask


def load(folder, label):
    """Return names and contents of a group's dumps, in acquisition order."""
    names = sorted(f for f in os.listdir(folder)
                   if f.startswith(label + "_") and f.endswith(".bin"))
    dumps = []
    for name in names:
        with open(os.path.join(folder, name), "rb") as fh:
            dumps.append(fh.read())
    return names, dumps


def to_bits(dump):
    """Bit i of the list is cell i (MSB first within each byte)."""
    return [(byte >> (7 - j)) & 1 for byte in dump for j in range(8)]


def build_mask(train):
    """
    Return (cells, golden, n_stable):
      cells    indices of the first N_CELLS stable cells
      golden   their reference values
      n_stable how many stable cells exist in total
    Stable = same value in every training dump.
    """
    first = train[0]
    stable = [i for i in range(len(first))
              if all(bits[i] == first[i] for bits in train)]
    if len(stable) < N_CELLS:
        raise ValueError(f"only {len(stable)} stable cells, {N_CELLS} needed")
    cells = stable[:N_CELLS]
    golden = [first[i] for i in cells]
    return cells, golden, len(stable)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="enr")
    ap.add_argument("--data", default="data")
    args = ap.parse_args()

    names, raw = load(args.data, args.label)
    if len(raw) <= TRAIN:
        print(f"Need more than {TRAIN} dumps, found {len(raw)}.")
        return
    dumps = [to_bits(d) for d in raw]
    train, test = dumps[:TRAIN], dumps[TRAIN:]

    cells, golden, n_stable = build_mask(train)
    total = len(train[0])
    print(f"Stable cells: {n_stable} / {total} ({100 * n_stable / total:.2f}%)")
    print(f"Used cells:   {N_CELLS} ({N_BLOCKS} blocks of {N_BLOCK})\n")

    # Errors of each validation dump on the used cells, split per BCH block.
    print(f"Validation, errors per block (at most {T} correctable):")
    total_err = 0
    worst = 0
    for name, bits in zip(names[TRAIN:], test):
        per_block = []
        for b in range(N_BLOCKS):
            block = range(b * N_BLOCK, (b + 1) * N_BLOCK)
            per_block.append(sum(bits[cells[i]] != golden[i] for i in block))
        total_err += sum(per_block)
        worst = max(worst, max(per_block))
        print(f"  {name}  {per_block}")

    ber = total_err / (N_CELLS * len(test))
    status = "OK" if worst <= T else "ABOVE t"
    print(f"\nResidual BER: {100 * ber:.4f}%")
    print(f"Worst block:  {worst} errors ({status})")


if __name__ == "__main__":
    main()