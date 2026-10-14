/*
 * crypto.h - Symmetric primitives used by the PUF key chain.
 *
 * Built on the PSA Crypto API. psa_crypto_init() must have been called
 * before (boot.c does it before checking the helper data signature).
 *
 * Key chain:
 *   K_master = SHA-256(w)
 *   K_auth   = HKDF-Expand(K_master, "puf-auth-v1", 32)  -> HMAC-SHA256
 *   K_enc    = HKDF-Expand(K_master, "puf-enc-v1",  32)  -> AES-256-GCM
 * HKDF-Extract is skipped (RFC 5869, sec. 3.3): K_master is already a
 * uniform 256-bit key. For 32 bytes, HKDF-Expand(K, info) = HMAC(K, info || 0x01).
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "psa/crypto.h"

#define CRYPTO_SHA256_LEN  32
#define CRYPTO_KEY_ID_LEN  8

#define CRYPTO_LABEL_AUTH  "puf-auth-v1"
#define CRYPTO_LABEL_ENC   "puf-enc-v1"

/* out = SHA-256(in). Returns 0 on success, -1 on error. */
int crypto_sha256(const uint8_t *in, size_t len, uint8_t out[CRYPTO_SHA256_LEN]);

/*
 * Key fingerprint: first 8 bytes of SHA-256(key). Same definition as the
 * key id written by host/enroll.py. It identifies the key without
 * revealing it. Returns 0 on success, -1 on error.
 */
int crypto_key_id(const uint8_t key[CRYPTO_SHA256_LEN],
                  uint8_t id[CRYPTO_KEY_ID_LEN]);

/*
 * Derive K_auth and K_enc from K_master straight into two volatile PSA
 * keys. They are NOT exportable: the firmware uses them through their
 * handles, their bytes never reach an application buffer.
 *   K_auth: HMAC-SHA256, sign/verify messages only
 *   K_enc:  AES-256, GCM encrypt/decrypt only
 * Returns PSA_SUCCESS or the PSA error. On error no key is left behind.
 */
psa_status_t crypto_derive_keys(const uint8_t k_master[CRYPTO_SHA256_LEN],
                                psa_key_id_t *k_auth, psa_key_id_t *k_enc);

/*
 * Self-test of K_auth: first 8 bytes of HMAC(K_auth, "puf-selftest").
 * host/server_keys.py computes the same value: if they match, C and
 * Python derived the same key. Returns PSA_SUCCESS or the PSA error.
 */
psa_status_t crypto_auth_selftest(psa_key_id_t k_auth, uint8_t out[8]);

/* ---------- Mutual authentication (challenge-response) ---------- */

#define CRYPTO_NONCE_LEN   16
#define CRYPTO_ID_LEN      6          /* device id: the MAC address */
#define CRYPTO_TAG_LEN     32         /* HMAC-SHA256 */

#define CRYPTO_ROLE_DEV    "dev"      /* tag computed by the device */
#define CRYPTO_ROLE_SRV    "srv"      /* tag computed by the server */

/* Random bytes from the PSA RNG (ESP32 hardware TRNG underneath). */
psa_status_t crypto_random(uint8_t *out, size_t len);

/*
 * tag = HMAC(K_auth, role || N_s || N_d || id), role = "dev" or "srv".
 * Every field has a fixed length, so the concatenation is unambiguous.
 */
psa_status_t crypto_auth_tag(psa_key_id_t k_auth, const char *role,
                             const uint8_t ns[CRYPTO_NONCE_LEN],
                             const uint8_t nd[CRYPTO_NONCE_LEN],
                             const uint8_t id[CRYPTO_ID_LEN],
                             uint8_t tag[CRYPTO_TAG_LEN]);

/*
 * Check a tag computed as above. Constant-time comparison inside PSA.
 * Returns PSA_SUCCESS if valid, PSA_ERROR_INVALID_SIGNATURE if not.
 */
psa_status_t crypto_auth_verify(psa_key_id_t k_auth, const char *role,
                                const uint8_t ns[CRYPTO_NONCE_LEN],
                                const uint8_t nd[CRYPTO_NONCE_LEN],
                                const uint8_t id[CRYPTO_ID_LEN],
                                const uint8_t tag[CRYPTO_TAG_LEN]);

/* Overwrite a buffer with zeros; the compiler cannot remove it. */
void crypto_zeroize(void *buf, size_t len);