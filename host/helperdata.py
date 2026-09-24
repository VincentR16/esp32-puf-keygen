#!/usr/bin/env python3
"""
helperdata.py - Binary format of the helper data.

Layout (little endian, no padding):

    offset  size   field
         0     4   magic "PUFH"
         4     1   version
         5     6   chip MAC
        11     4   SRAM region address
        15     2   SRAM region size in bytes
        17     1   n     BCH block length
        18     1   k     message bits per block
        19     1   t     correctable errors per block
        20     1   blocks
        21   1024   mask, one bit per cell (1 = used)
      1045    128   W, 4 blocks of 255 bits
      1173     64   ECDSA P-256 signature over every previous byte

Bits are packed MSB first: bit i sits in byte i//8, at position 7-(i%8).
The same convention is used for the mask, for W and for the SHA-256 of w,
and the C firmware must follow it exactly.

The signature is ECDSA P-256 over the payload, stored raw as r || s.
"""

import struct
from dataclasses import dataclass, field

import fuzzy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

MAGIC = b"PUFH"
VERSION = 1
HEADER = "<4sB6sIHBBBB"          # 21 bytes
HEADER_SIZE = struct.calcsize(HEADER)
SIG_SIZE = 64


def bits_to_bytes(bits):
    """Bit list -> bytes, MSB first."""
    return fuzzy.pack_bits(bits)


def bytes_to_bits(data, count=None):
    """bytes -> bit list, MSB first. Keeps only the first `count` bits."""
    bits = [(b >> (7 - j)) & 1 for b in data for j in range(8)]
    return bits if count is None else bits[:count]


@dataclass
class HelperData:
    mac: bytes                  # 6 bytes
    region_addr: int            # address of the .noinit buffer
    region_bytes: int           # size of the SRAM region
    mask: bytes                 # one bit per cell
    w_helper: bytes             # W, packed bits
    version: int = VERSION
    n: int = fuzzy.N
    k: int = fuzzy.K
    t: int = fuzzy.T
    blocks: int = fuzzy.BLOCKS
    signature: bytes = field(default=b"")

    # ---------- build ----------

    @classmethod
    def build(cls, mac, region_addr, region_bits, cells, helper_ints):
        """Build the helper data from the enrollment output."""
        mask = [0] * region_bits
        for i in cells:
            mask[i] = 1
        bits = []
        for h in helper_ints:
            bits += fuzzy.int_to_bits(h, fuzzy.N)
        return cls(mac=mac,
                   region_addr=region_addr,
                   region_bytes=region_bits // 8,
                   mask=bits_to_bytes(mask),
                   w_helper=bits_to_bytes(bits))

    # ---------- serialize ----------

    def payload(self):
        """Every byte covered by the signature."""
        head = struct.pack(HEADER, MAGIC, self.version, self.mac,
                           self.region_addr, self.region_bytes,
                           self.n, self.k, self.t, self.blocks)
        return head + self.mask + self.w_helper

    def to_bytes(self):
        return self.payload() + self.signature

    @classmethod
    def from_bytes(cls, data):
        if len(data) < HEADER_SIZE:
            raise ValueError("helper data too short")
        (magic, version, mac, addr, region_bytes,
         n, k, t, blocks) = struct.unpack(HEADER, data[:HEADER_SIZE])
        if magic != MAGIC:
            raise ValueError("bad magic")
        if version != VERSION:
            raise ValueError(f"unsupported version {version}")

        w_bytes = (n * blocks + 7) // 8
        expected = HEADER_SIZE + region_bytes + w_bytes + SIG_SIZE
        if len(data) != expected:
            raise ValueError(f"expected {expected} bytes, got {len(data)}")

        start = HEADER_SIZE
        mask = data[start:start + region_bytes]
        start += region_bytes
        w_helper = data[start:start + w_bytes]
        start += w_bytes
        return cls(mac=mac, region_addr=addr, region_bytes=region_bytes,
                   mask=mask, w_helper=w_helper, version=version,
                   n=n, k=k, t=t, blocks=blocks,
                   signature=data[start:])

    # ---------- signature ----------

    def sign(self, private_key):
        """Sign the payload. Signature stored raw as r || s, like PSA wants."""
        der = private_key.sign(self.payload(), ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        self.signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def verify(self, public_key):
        """True if the signature matches the payload."""
        if len(self.signature) != SIG_SIZE:
            return False
        der = utils.encode_dss_signature(
            int.from_bytes(self.signature[:32], "big"),
            int.from_bytes(self.signature[32:], "big"))
        try:
            public_key.verify(der, self.payload(), ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    # ---------- use ----------

    def cells(self):
        """Indices of the cells selected by the mask, in address order."""
        return [i for i, b in enumerate(bytes_to_bits(self.mask)) if b]

    def helper_ints(self):
        """W as one integer per BCH block."""
        bits = bytes_to_bits(self.w_helper, self.n * self.blocks)
        return [fuzzy.bits_to_int(bits[b * self.n:(b + 1) * self.n])
                for b in range(self.blocks)]

    def describe(self):
        mac = ":".join(f"{b:02x}" for b in self.mac)
        return (f"version {self.version}, MAC {mac}, "
                f"region 0x{self.region_addr:08X} ({self.region_bytes} bytes), "
                f"BCH({self.n},{self.k},t={self.t}) x{self.blocks}, "
                f"{len(self.cells())} cells, "
                f"{'signed' if self.signature else 'UNSIGNED'}")