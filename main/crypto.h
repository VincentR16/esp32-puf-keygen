/*
 * crypto.h - Symmetric primitives used by the PUF key chain.
 *
 * Thin wrappers over the PSA Crypto API, so that the rest of the module
 * does not depend on PSA types. psa_crypto_init() must have been called
 * before (boot.c does it before checking the helper data signature).
 *
 * HKDF (K_auth, K_enc) will be added here in step (c).
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_SHA256_LEN  32
#define CRYPTO_KEY_ID_LEN  8

/* out = SHA-256(in). Returns 0 on success, -1 on error. */
int crypto_sha256(const uint8_t *in, size_t len, uint8_t out[CRYPTO_SHA256_LEN]);

/*
 * Key fingerprint: first 8 bytes of SHA-256(key). Same definition as the
 * key id written by host/enroll.py. It identifies the key without
 * revealing it. Returns 0 on success, -1 on error.
 */
int crypto_key_id(const uint8_t key[CRYPTO_SHA256_LEN],
                  uint8_t id[CRYPTO_KEY_ID_LEN]);

/* Overwrite a buffer with zeros; the compiler cannot remove it. */
void crypto_zeroize(void *buf, size_t len);