#!/usr/bin/env python3
"""
analyze.py — Confronto tra gruppi di dump PUF.

Legge data/<label>_NNN.bin e per ogni gruppo calcola:
  - uniformity media (percentuale di bit a 1)
  - intra-HD a coppie (media, minimo, massimo)
  - percentuale di celle stabili su tutte le letture del gruppo
Poi calcola l'HD media tra gruppi diversi.

Uso:
    python host/analyze.py
"""

import argparse
import os
from collections import defaultdict
from itertools import combinations
from statistics import mean


def hd(a, b):
    """Distanza di Hamming: numero di bit diversi tra due dump."""
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def ones(a):
    """Numero di bit a 1 nel dump."""
    return sum(x.bit_count() for x in a)


def stable_fraction(dumps):
    """Frazione di bit che hanno lo stesso valore in TUTTI i dump."""
    nbits = len(dumps[0]) * 8
    stable = 0
    for i in range(len(dumps[0])):
        and_all, or_all = 0xFF, 0x00
        for d in dumps:
            and_all &= d[i]
            or_all |= d[i]
        # stabile a 1: presente nell'AND; stabile a 0: assente nell'OR
        stable += and_all.bit_count() + (~or_all & 0xFF).bit_count()
    return stable / nbits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    args = ap.parse_args()

    groups = defaultdict(list)
    for f in sorted(os.listdir(args.data)):
        if f.endswith(".bin"):
            label = f.rsplit("_", 1)[0]
            with open(os.path.join(args.data, f), "rb") as fh:
                groups[label].append(fh.read())

    if not groups:
        print("Nessun dump trovato in", args.data)
        return

    for label, dumps in groups.items():
        nbits = len(dumps[0]) * 8
        print(f"=== {label}: {len(dumps)} dump da {nbits} bit ===")
        print(f"  uniformity media  {100 * mean(ones(d) for d in dumps) / nbits:.2f}%")
        if len(dumps) >= 2:
            hds = [100 * hd(a, b) / nbits for a, b in combinations(dumps, 2)]
            print(f"  intra-HD media    {mean(hds):.2f}%   "
                  f"(min {min(hds):.2f}%, max {max(hds):.2f}%)")
            print(f"  celle stabili     {100 * stable_fraction(dumps):.2f}%  "
                  f"su {len(dumps)} letture")
        print()

    for l1, l2 in combinations(list(groups), 2):
        hds = [100 * hd(a, b) / (len(a) * 8) for a in groups[l1] for b in groups[l2]]
        print(f"HD media tra {l1} e {l2}: {mean(hds):.2f}%")


if __name__ == "__main__":
    main()
