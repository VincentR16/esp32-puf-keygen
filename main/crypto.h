/*
 * crypto.h - Symmetric primitives used by the PUF key chain.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "psa/crypto.h"

#define CRYPTO_SHA256_LEN  32

#define CRYPTO_LABEL_AUTH  "puf-auth-v1"
#define CRYPTO_LABEL_ENC   "puf-enc-v1"

/* out = SHA-256(in). Returns 0 on success, -1 on error. */
int crypto_sha256(const uint8_t *in, size_t len, uint8_t out[CRYPTO_SHA256_LEN]);



psa_status_t crypto_derive_keys(const uint8_t k_master[CRYPTO_SHA256_LEN],
                                psa_key_id_t *k_auth, psa_key_id_t *k_enc);

/*  Mutual authentication (challenge-response)  */

#define CRYPTO_NONCE_LEN   16
#define CRYPTO_ID_LEN      6          /* device id: the MAC address */
#define CRYPTO_TAG_LEN     32         /* HMAC-SHA256 */

#define CRYPTO_ROLE_DEV    "dev"      /* tag computed by the device */
#define CRYPTO_ROLE_SRV    "srv"      /* tag computed by the server */

/* Random bytes from the PSA RNG (ESP32 hardware TRNG underneath). */
psa_status_t crypto_random(uint8_t *out, size_t len);


psa_status_t crypto_auth_tag(psa_key_id_t k_auth, const char *role,
                             const uint8_t ns[CRYPTO_NONCE_LEN],
                             const uint8_t nd[CRYPTO_NONCE_LEN],
                             const uint8_t id[CRYPTO_ID_LEN],
                             uint8_t tag[CRYPTO_TAG_LEN]);


psa_status_t crypto_auth_verify(psa_key_id_t k_auth, const char *role,
                                const uint8_t ns[CRYPTO_NONCE_LEN],
                                const uint8_t nd[CRYPTO_NONCE_LEN],
                                const uint8_t id[CRYPTO_ID_LEN],
                                const uint8_t tag[CRYPTO_TAG_LEN]);

/* ---------- Encrypted data (AES-256-GCM with a session key) ---------- */

#define CRYPTO_GCM_TAG_LEN 16

psa_status_t crypto_session_key(psa_key_id_t k_enc,
                                const uint8_t ns[CRYPTO_NONCE_LEN],
                                const uint8_t nd[CRYPTO_NONCE_LEN],
                                psa_key_id_t *k_sess);


psa_status_t crypto_seal(psa_key_id_t k_sess, const uint8_t id[CRYPTO_ID_LEN],
                         uint32_t seq, const uint8_t *pt, size_t pt_len,
                         uint8_t *out, size_t out_size, size_t *out_len);

/* Overwrite a buffer with zeros; the compiler cannot remove it. */
void crypto_zeroize(void *buf, size_t len);