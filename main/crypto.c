/*
 * crypto.c - Symmetric primitives used by the PUF key chain.
 */

#include <string.h>

#include "psa/crypto.h"

#include "crypto.h"

int crypto_sha256(const uint8_t *in, size_t len, uint8_t out[CRYPTO_SHA256_LEN])
{
    size_t out_len = 0;
    psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256, in, len,
                                       out, CRYPTO_SHA256_LEN, &out_len);
    return (st == PSA_SUCCESS && out_len == CRYPTO_SHA256_LEN) ? 0 : -1;
}

int crypto_key_id(const uint8_t key[CRYPTO_SHA256_LEN],
                  uint8_t id[CRYPTO_KEY_ID_LEN])
{
    uint8_t h[CRYPTO_SHA256_LEN];
    int ret = crypto_sha256(key, CRYPTO_SHA256_LEN, h);
    if (ret == 0) {
        memcpy(id, h, CRYPTO_KEY_ID_LEN);
    }
    crypto_zeroize(h, sizeof(h));
    return ret;
}

/*
 * A plain memset on a buffer that is never read again is a dead store,
 * and the compiler may delete it. Writing through a volatile pointer
 * forces every store; the barrier stops it from being moved.
 */
void crypto_zeroize(void *buf, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) {
        *p++ = 0;
    }
    __asm__ __volatile__("" ::: "memory");
}