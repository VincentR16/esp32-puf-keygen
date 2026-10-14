/*
 * crypto.c - Symmetric primitives used by the PUF key chain.
 * See crypto.h for the key chain.
 */

#include <string.h>

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
 * One HKDF-Expand(secret, info, 32) straight into a PSA key.
 * PSA lets a derivation produce a key (output_key) only if its secret
 * came in as a key with the DERIVE usage, not as raw bytes: that is
 * why the secret (K_master or K_enc) is passed as a key handle here.
 */
static psa_status_t hkdf_expand_key(psa_key_id_t secret,
                                    const uint8_t *info, size_t info_len,
                                    const psa_key_attributes_t *attr,
                                    psa_key_id_t *key)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t st;

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    if (st == PSA_SUCCESS) {
        /* For HKDF-Expand the secret is the PRK. */
        st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          secret);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                            info, info_len);
    }
    if (st == PSA_SUCCESS) {
        /* Bit size and type come from attr: 256 bits read from the stream. */
        st = psa_key_derivation_output_key(attr, &op, key);
    }
    psa_key_derivation_abort(&op);  /* wipes the operation state */
    return st;
}

psa_status_t crypto_derive_keys(const uint8_t k_master[CRYPTO_SHA256_LEN],
                                psa_key_id_t *k_auth, psa_key_id_t *k_enc)
{
    psa_status_t st;

    /* K_master enters PSA as a derivation-only key, used for the two
     * HKDF-Expand calls and destroyed right after. */
    psa_key_attributes_t master = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&master, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&master, 256);
    psa_set_key_usage_flags(&master, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&master, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));

    psa_key_id_t km;
    st = psa_import_key(&master, k_master, CRYPTO_SHA256_LEN, &km);
    if (st != PSA_SUCCESS) {
        return st;
    }

    /* No PSA_KEY_USAGE_EXPORT: the bytes cannot be read back. */
    psa_key_attributes_t auth = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&auth, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&auth, 256);
    psa_set_key_usage_flags(&auth, PSA_KEY_USAGE_SIGN_MESSAGE |
                                   PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&auth, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    /* K_enc never encrypts: it only derives the session keys. */
    psa_key_attributes_t enc = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&enc, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&enc, 256);
    psa_set_key_usage_flags(&enc, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&enc, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));

    st = hkdf_expand_key(km, (const uint8_t *)CRYPTO_LABEL_AUTH,
                         strlen(CRYPTO_LABEL_AUTH), &auth, k_auth);
    if (st == PSA_SUCCESS) {
        st = hkdf_expand_key(km, (const uint8_t *)CRYPTO_LABEL_ENC,
                             strlen(CRYPTO_LABEL_ENC), &enc, k_enc);
        if (st != PSA_SUCCESS) {
            psa_destroy_key(*k_auth);   /* all or nothing */
        }
    }
    psa_destroy_key(km);            /* PSA wipes the key material */
    return st;
}

psa_status_t crypto_random(uint8_t *out, size_t len)
{
    return psa_generate_random(out, len);
}

#define AUTH_ROLE_LEN  3
#define AUTH_MSG_LEN   (AUTH_ROLE_LEN + 2 * CRYPTO_NONCE_LEN + CRYPTO_ID_LEN)

/* role || N_s || N_d || id, 41 bytes. Returns -1 on a bad role. */
static int auth_msg(uint8_t msg[AUTH_MSG_LEN], const char *role,
                    const uint8_t *ns, const uint8_t *nd, const uint8_t *id)
{
    if (strlen(role) != AUTH_ROLE_LEN) {
        return -1;
    }
    uint8_t *p = msg;
    memcpy(p, role, AUTH_ROLE_LEN);    p += AUTH_ROLE_LEN;
    memcpy(p, ns, CRYPTO_NONCE_LEN);   p += CRYPTO_NONCE_LEN;
    memcpy(p, nd, CRYPTO_NONCE_LEN);   p += CRYPTO_NONCE_LEN;
    memcpy(p, id, CRYPTO_ID_LEN);
    return 0;
}

psa_status_t crypto_auth_tag(psa_key_id_t k_auth, const char *role,
                             const uint8_t ns[CRYPTO_NONCE_LEN],
                             const uint8_t nd[CRYPTO_NONCE_LEN],
                             const uint8_t id[CRYPTO_ID_LEN],
                             uint8_t tag[CRYPTO_TAG_LEN])
{
    uint8_t msg[AUTH_MSG_LEN];
    size_t tag_len = 0;
    if (auth_msg(msg, role, ns, nd, id) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    psa_status_t st = psa_mac_compute(k_auth, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                                      msg, sizeof(msg),
                                      tag, CRYPTO_TAG_LEN, &tag_len);
    if (st == PSA_SUCCESS && tag_len != CRYPTO_TAG_LEN) {
        st = PSA_ERROR_GENERIC_ERROR;
    }
    return st;
}

psa_status_t crypto_auth_verify(psa_key_id_t k_auth, const char *role,
                                const uint8_t ns[CRYPTO_NONCE_LEN],
                                const uint8_t nd[CRYPTO_NONCE_LEN],
                                const uint8_t id[CRYPTO_ID_LEN],
                                const uint8_t tag[CRYPTO_TAG_LEN])
{
    uint8_t msg[AUTH_MSG_LEN];
    if (auth_msg(msg, role, ns, nd, id) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    /* Recomputes the HMAC and compares in constant time. */
    return psa_mac_verify(k_auth, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                          msg, sizeof(msg), tag, CRYPTO_TAG_LEN);
}

/* ---------- Encrypted data ---------- */

#define SESS_LABEL      "puf-sess-v1"
#define SESS_LABEL_LEN  (sizeof(SESS_LABEL) - 1)
#define DATA_AD_TAG     "data"
#define DATA_AD_LEN     (4 + CRYPTO_ID_LEN + 4)
#define GCM_NONCE_LEN   12

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

psa_status_t crypto_session_key(psa_key_id_t k_enc,
                                const uint8_t ns[CRYPTO_NONCE_LEN],
                                const uint8_t nd[CRYPTO_NONCE_LEN],
                                psa_key_id_t *k_sess)
{
    /* info = "puf-sess-v1" || N_s || N_d */
    uint8_t info[SESS_LABEL_LEN + 2 * CRYPTO_NONCE_LEN];
    memcpy(info, SESS_LABEL, SESS_LABEL_LEN);
    memcpy(info + SESS_LABEL_LEN, ns, CRYPTO_NONCE_LEN);
    memcpy(info + SESS_LABEL_LEN + CRYPTO_NONCE_LEN, nd, CRYPTO_NONCE_LEN);

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);  /* device only sends */
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    return hkdf_expand_key(k_enc, info, sizeof(info), &attr, k_sess);
}

psa_status_t crypto_seal(psa_key_id_t k_sess, const uint8_t id[CRYPTO_ID_LEN],
                         uint32_t seq, const uint8_t *pt, size_t pt_len,
                         uint8_t *out, size_t out_size, size_t *out_len)
{
    /* nonce = 0^8 || seq: unique as long as seq never repeats */
    uint8_t nonce[GCM_NONCE_LEN] = { 0 };
    put_be32(nonce + 8, seq);

    /* AD = "data" || id || seq */
    uint8_t ad[DATA_AD_LEN];
    memcpy(ad, DATA_AD_TAG, 4);
    memcpy(ad + 4, id, CRYPTO_ID_LEN);
    put_be32(ad + 4 + CRYPTO_ID_LEN, seq);

    return psa_aead_encrypt(k_sess, PSA_ALG_GCM, nonce, sizeof(nonce),
                            ad, sizeof(ad), pt, pt_len,
                            out, out_size, out_len);
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