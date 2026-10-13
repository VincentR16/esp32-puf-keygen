/*
 * fuzzy.c - Code-offset fuzzy extractor, reconstruction side.
 * Port of host/fuzzy.py (bch_decode, reproduce). See fuzzy.h.
 */

#include <string.h>

#include "crypto.h"
#include "fuzzy.h"

#define PRIM_POLY  0x11D            /* x^8 + x^4 + x^3 + x^2 + 1 */
#define NSYND      (2 * FUZZY_T)    /* syndromes S_1 ... S_2t */
#define LAM_MAX    (4 * FUZZY_T)    /* room for Lambda during Berlekamp-Massey */

/* ---------- GF(2^8) with log/antilog tables ---------- */

static uint8_t EXP[510];            /* EXP[i] = alpha^i, doubled to skip a mod */
static uint8_t LOG[256];            /* LOG[alpha^i] = i, LOG[0] unused */

void fuzzy_init(void)
{
    unsigned v = 1;
    for (int i = 0; i < 255; i++) {
        EXP[i] = (uint8_t)v;
        LOG[v] = (uint8_t)i;
        v <<= 1;                    /* multiply by alpha (that is, by x) */
        if (v & 0x100) {
            v ^= PRIM_POLY;         /* reduce x^8 */
        }
    }
    for (int i = 255; i < 510; i++) {
        EXP[i] = EXP[i - 255];
    }
}

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    return EXP[LOG[a] + LOG[b]];
}

static uint8_t gf_div(uint8_t a, uint8_t b)
{
    if (a == 0) {
        return 0;
    }
    return EXP[(LOG[a] + 255 - LOG[b]) % 255];
}

/* ---------- Bits of a packed buffer, MSB first ---------- */

static int get_bit(const uint8_t *buf, size_t i)
{
    return (buf[i / 8] >> (7 - i % 8)) & 1;
}

static void flip_bit(uint8_t *buf, size_t i)
{
    buf[i / 8] ^= 0x80 >> (i % 8);
}

/* ---------- BCH decoder ---------- */

/* S_j = r(alpha^j), j = 1 ... 2t. Returns 1 if all of them are zero. */
static int syndromes(const uint8_t r[FUZZY_N], uint8_t synd[NSYND])
{
    int all_zero = 1;
    for (int j = 1; j <= NSYND; j++) {
        uint8_t s = 0;
        for (int i = 0; i < FUZZY_N; i++) {
            if (r[i]) {
                s ^= EXP[(i * j) % 255];
            }
        }
        synd[j - 1] = s;
        if (s) {
            all_zero = 0;
        }
    }
    return all_zero;
}

/*
 * Berlekamp-Massey: error locator Lambda(x) from the syndromes.
 * lam[0..L] are its coefficients. Returns L (its degree), or -1 if the
 * work arrays would overflow (cannot happen for valid input, checked anyway).
 */
static int berlekamp_massey(const uint8_t synd[NSYND], uint8_t lam[LAM_MAX])
{
    uint8_t prev[LAM_MAX], old[LAM_MAX];
    int lam_len = 1, prev_len = 1, old_len;
    int L = 0, shift = 1;
    uint8_t last_d = 1;

    memset(lam, 0, LAM_MAX);
    memset(prev, 0, LAM_MAX);
    lam[0] = 1;
    prev[0] = 1;

    for (int n = 0; n < NSYND; n++) {
        /* discrepancy: how wrong the current Lambda is on S_{n+1} */
        uint8_t d = synd[n];
        for (int i = 1; i <= L; i++) {
            if (i < lam_len) {
                d ^= gf_mul(lam[i], synd[n - i]);
            }
        }
        if (d == 0) {
            shift++;
            continue;
        }

        memcpy(old, lam, LAM_MAX);
        old_len = lam_len;

        /* Lambda(x) -= (d / last_d) * x^shift * prev(x) */
        uint8_t coef = gf_div(d, last_d);
        int need = prev_len + shift;
        if (need > LAM_MAX) {
            return -1;
        }
        if (need > lam_len) {
            lam_len = need;         /* the new coefficients are already 0 */
        }
        for (int i = 0; i < prev_len; i++) {
            lam[i + shift] ^= gf_mul(coef, prev[i]);
        }

        if (2 * L <= n) {
            L = n + 1 - L;
            memcpy(prev, old, LAM_MAX);
            prev_len = old_len;
            last_d = d;
            shift = 1;
        } else {
            shift++;
        }
    }

    /* Python returns lam[:L + 1]: drop anything above degree L. */
    for (int i = L + 1; i < LAM_MAX; i++) {
        lam[i] = 0;
    }
    return L;
}

/*
 * Decode one received block r (one bit per byte, r[i] = coefficient of x^i).
 * Corrects r in place and writes the error positions into pos.
 * Returns the number of errors, or -1 if the block cannot be decoded.
 */
static int bch_decode(uint8_t r[FUZZY_N], int pos[FUZZY_T])
{
    uint8_t synd[NSYND];
    uint8_t lam[LAM_MAX];
    int ret = -1;
    int L, found = 0;

    if (syndromes(r, synd)) {
        ret = 0;                    /* already a codeword */
        goto out;
    }

    L = berlekamp_massey(synd, lam);
    if (L < 0 || L > FUZZY_T) {
        goto out;                   /* more than t errors */
    }

    /* Chien search: Lambda(alpha^-i) = 0  ->  error at position i */
    for (int i = 0; i < FUZZY_N; i++) {
        int e = (255 - i) % 255;    /* exponent of alpha^-i */
        uint8_t v = 0;
        for (int k = 0; k <= L; k++) {
            v ^= gf_mul(lam[k], EXP[(e * k) % 255]);
        }
        if (v == 0) {
            if (found == FUZZY_T) {
                goto out;           /* more roots than possible */
            }
            pos[found++] = i;
        }
    }
    if (found != L) {
        goto out;                   /* Lambda does not split: undecodable */
    }

    for (int i = 0; i < found; i++) {
        r[pos[i]] ^= 1;
    }

    /* The result must be a codeword: all 2t syndromes zero. Equivalent to
     * r mod g(x) == 0 in fuzzy.py, since the roots of g are alpha^1..alpha^2t. */
    if (!syndromes(r, synd)) {
        goto out;
    }
    ret = found;

out:
    crypto_zeroize(synd, sizeof(synd));
    crypto_zeroize(lam, sizeof(lam));
    return ret;
}

/* ---------- Code-offset reconstruction ---------- */

int fuzzy_reproduce(uint8_t *w, const uint8_t *W, size_t blocks, int *errs)
{
    uint8_t r[FUZZY_N];             /* c' of one block: secret, since W is public */
    int pos[FUZZY_T];
    int ret = 0;

    for (size_t b = 0; b < blocks; b++) {
        size_t base = b * FUZZY_N;

        for (int i = 0; i < FUZZY_N; i++) {
            r[i] = (uint8_t)(get_bit(w, base + i) ^ get_bit(W, base + i));
        }

        int n = bch_decode(r, pos);
        errs[b] = n;
        if (n < 0) {
            ret = -1;
            continue;               /* keep going: errs reports every block */
        }

        /* w = c XOR W = w' XOR e: flip the same positions in w' */
        for (int i = 0; i < n; i++) {
            flip_bit(w, base + pos[i]);
        }
    }

    crypto_zeroize(r, sizeof(r));
    crypto_zeroize(pos, sizeof(pos));
    return ret;
}