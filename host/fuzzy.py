"""
fuzzy.py - Fuzzy extractor (code-offset) with BCH(255, 179, t=10).
 
Enrollment:      W = w XOR c, where c is the BCH codeword of a random x
Reconstruction:  c' = w' XOR W  ->  BCH decode  ->  c  ->  w = c XOR W
Key:             K_master = SHA-256(w)
 
w has 1020 bits, split into 4 blocks of 255 bits, one codeword each.
Standard library only: this is the reference for the C version.
 
Run it directly to self-test the BCH code:
    python3 host/fuzzy.py
"""

import hashlib
import secrets

N = 255
T = 10
BLOCKS = 4
PRIM_POLY = 0x11d  # x^8 + x^4 + x^3 + x^2 + 1

EXP = [0] * 510
LOG = [0] * 256
_v = 1

for _i in range(255):
    EXP[_i] = _v
    LOG[_v] = _i
    _v <<= 1
    if _v & 0x100:
        _v ^= PRIM_POLY

for _i in range(255, 510):
    EXP[_i] = EXP[_i - 255]


def gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]

def gf_div(a, b):
    if a == 0:
        return 0
    return EXP[(LOG[a] - LOG[b]) % 255]

def poly_mul(a, b):
    """Product of two binary polynomials."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        b >>= 1
    return r

def poly_mod(a, m):
    """Remainder of a divided by m (binary polynomials)."""
    dm = m.bit_length() - 1
    while a.bit_length() - 1 >= dm:
        a ^= m << (a.bit_length() - 1 - dm)
    return a

def minimal_poly(i):
    """Minimal polynomial of alpha^i and its cyclotomic coset."""
    coset = []
    j = i % 255
    while j not in coset:
        coset.append(j)
        j = (2 * j) % 255
    coeffs = [1]                      # product of (x + alpha^e), over GF(2^8)
    for e in coset:
        root = EXP[e]
        new = [0] * (len(coeffs) + 1)
        for d, c in enumerate(coeffs):
            new[d + 1] ^= c
            new[d] ^= gf_mul(c, root)
        coeffs = new
    assert all(c in (0, 1) for c in coeffs)   # the result is binary
    return sum(c << d for d, c in enumerate(coeffs)), frozenset(coset)

def generator_poly():
    """g(x) = LCM of the minimal polynomials of alpha^1 ... alpha^2t."""
    g, seen = 1, set()
    for i in range(1, 2 * T + 1):
        m, coset = minimal_poly(i)
        if coset not in seen:
            seen.add(coset)
            g = poly_mul(g, m)
    return g

GEN = generator_poly()
K = N - (GEN.bit_length() - 1)        # message bits per block
assert K == 179, K

def bch_encode(msg):
    """K-bit message -> N-bit codeword. Systematic: parity in the low 76 bits."""
    shifted = msg << (N - K)
    return shifted | poly_mod(shifted, GEN)
 
 
def syndromes(r):
    """S_j = r(alpha^j) for j = 1 ... 2t."""
    out = []
    for j in range(1, 2 * T + 1):
        s = 0
        for i in range(N):
            if (r >> i) & 1:
                s ^= EXP[(i * j) % 255]
        out.append(s)
    return out
 
 
def berlekamp_massey(synd):
    """Error locator polynomial Lambda(x), as a list of GF(2^8) coefficients."""
    lam, prev = [1], [1]
    length, shift, last_d = 0, 1, 1
    for n in range(2 * T):
        d = synd[n]
        for i in range(1, length + 1):
            if i < len(lam):
                d ^= gf_mul(lam[i], synd[n - i])
        if d == 0:
            shift += 1
            continue
        old = lam[:]
        coef = gf_div(d, last_d)
        lam += [0] * max(0, len(prev) + shift - len(lam))
        for i, p in enumerate(prev):
            lam[i + shift] ^= gf_mul(coef, p)
        if 2 * length <= n:
            length, prev, last_d, shift = n + 1 - length, old, d, 1
        else:
            shift += 1
    return lam[:length + 1], length
 
 
def bch_decode(r):
    """
    N-bit received word -> (codeword, number of corrected errors),
    or (None, None) if the errors cannot be corrected.
    """
    synd = syndromes(r)
    if not any(synd):
        return r, 0
    lam, length = berlekamp_massey(synd)
    if length > T:
        return None, None
    # Chien search: Lambda(alpha^-i) = 0  ->  error at position i
    errors = []
    for i in range(N):
        x = EXP[(255 - i) % 255]
        v, xp = 0, 1
        for c in lam:
            v ^= gf_mul(c, xp)
            xp = gf_mul(xp, x)
        if v == 0:
            errors.append(i)
    if len(errors) != length:
        return None, None
    for i in errors:
        r ^= 1 << i
    if poly_mod(r, GEN) != 0:
        return None, None
    return r, len(errors)

def bits_to_int(bits):
    """Bit i of the list -> coefficient of x^i."""
    v = 0
    for i, b in enumerate(bits):
        v |= b << i
    return v
 
 
def int_to_bits(v, n):
    return [(v >> i) & 1 for i in range(n)]
 
 
def pack_bits(bits):
    """Bit list -> bytes, MSB first, zero-padded at the end."""
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 0x80 >> (i % 8)
    return bytes(out)
 
 
# ---------- Fuzzy extractor ----------
 
def derive_key(w):
    """K_master = SHA-256 of w packed into bytes."""
    return hashlib.sha256(pack_bits(w)).digest()
 
 
def generate(w):
    """Enrollment: w (1020 bits) -> (helper W as 4 ints, K_master)."""
    assert len(w) == N * BLOCKS
    helper = []
    for b in range(BLOCKS):
        wb = bits_to_int(w[b * N:(b + 1) * N])
        c = bch_encode(secrets.randbits(K))
        helper.append(wb ^ c)
    return helper, derive_key(w)
 
 
def reproduce(w_noisy, helper):
    """
    Reconstruction: noisy w' + helper W -> (K_master, errors per block).
    K_master is None if at least one block cannot be decoded.
    """
    w, errs, failed = [], [], False
    for b in range(BLOCKS):
        wb = bits_to_int(w_noisy[b * N:(b + 1) * N])
        c, nerr = bch_decode(wb ^ helper[b])
        errs.append(nerr)
        if c is None:
            failed = True
            continue
        w += int_to_bits(c ^ helper[b], N)
    return (None if failed else derive_key(w)), errs
 
 

 
def _self_test(trials=200):
    import random
    rng = random.Random(1)
    print(f"BCH({N}, {K}, t={T}), generator degree {N - K}\n")
    print(f"{'errors':>7} {'corrected':>10} {'detected':>9} {'wrong':>6}")
    for n_err in list(range(0, T + 1)) + [T + 1, T + 2, T + 5]:
        ok = det = wrong = 0
        for _ in range(trials):
            c = bch_encode(rng.getrandbits(K))
            e = 0
            for pos in rng.sample(range(N), n_err):
                e |= 1 << pos
            d, _ = bch_decode(c ^ e)
            if d is None:
                det += 1
            elif d == c:
                ok += 1
            else:
                wrong += 1
        print(f"{n_err:>7} {ok:>10} {det:>9} {wrong:>6}")
    print("\nUp to t errors every word must be corrected. Beyond t the decoder")
    print("should report failure ('detected'); 'wrong' is a silent miscorrection.")
 
 
if __name__ == "__main__":
    _self_test()
 