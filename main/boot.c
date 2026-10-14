/*
 * boot.c - Step 3c: read the helper data from NVS, check its signature
 * and its consistency with this board, then rebuild the keys:
 *   w' (masked cells) -> BCH decoding with W -> w -> SHA-256 -> K_master
 *   K_master -> HKDF-Expand -> K_auth, K_enc (non-exportable PSA keys)
 *
 * If a block cannot be decoded the device halts without a key.
 * K_master and every intermediate buffer are zeroized after use.
 *
 * Then (step 4, transport only): join the WiFi, connect to the server,
 * send HELLO and print the answer. Nothing is encrypted yet.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "heap_memory_layout.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "psa/crypto.h"

#include "crypto.h"
#include "fuzzy.h"
#include "net.h"
#include "pk_prov.h"
#include "puf.h"
#include "puf_region.h"

/*
 * DEBUG ONLY. Prints w' (before correction) on the serial port, for
 * host/check_wprime.py. w' is almost the key: with it on, the PUF
 * response leaves the chip. Keep it at 0.
 */
#define PUF_DEBUG_DUMP 0

/*
 * Prints the errors corrected in each block. It reveals how noisy this
 * boot was, not the key; useful for the report, can be turned off.
 */
#define PUF_DEBUG_ERRORS 1

#define HD_SIZE     1237            /* helper data, bytes */
#define HD_SIG      64              /* ECDSA signature r || s, at the end */
#define HD_PAYLOAD  (HD_SIZE - HD_SIG)  /* bytes covered by the signature */
#define HD_MASK     21              /* offset of the mask */
#define HD_W        1045            /* offset of W */
#define HD_W_LEN    128             /* bytes of W */

#define W_MAX_BYTES 128             /* room for w' (1020 bits + padding) */

/* Keep the heap away from the PUF region: nothing will ever write it. */
SOC_RESERVE_MEMORY_REGION(PUF_ADDR, PUF_ADDR + PUF_SIZE, puf_reserved);

static uint8_t snapshot[PUF_SIZE];
static uint8_t hd[HD_SIZE];

/* The only key material that outlives rebuild_key(): PSA handles. */
static psa_key_id_t k_auth;
static psa_key_id_t k_enc;

static uint16_t le16(const uint8_t *p) { return p[0] | (p[1] << 8); }
static uint32_t le32(const uint8_t *p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Fail closed: print the reason and do nothing else. */
static void halt(const char *why)
{
    printf("HALT: %s\n", why);
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

/* Same, with the PSA status code to help debugging. */
static void halt_status(const char *why, psa_status_t st)
{
    printf("HALT: %s (PSA status %d)\n", why, (int)st);
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

static void print_hex(const char *tag, const uint8_t *buf, size_t len)
{
    printf("%s ", tag);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void load_helper_data(void)
{
    /* Never erase NVS on error, as the ESP-IDF examples do:
     * the helper data lives there and cannot be regenerated. */
    if (nvs_flash_init() != ESP_OK) {
        halt("NVS init failed");
    }

    nvs_handle_t h;
    if (nvs_open("puf", NVS_READONLY, &h) != ESP_OK) {
        halt("namespace 'puf' not found");
    }
    size_t len = sizeof(hd);
    esp_err_t err = nvs_get_blob(h, "hd", hd, &len);
    nvs_close(h);

    if (err != ESP_OK) {
        halt("blob 'hd' not found or too large");
    }
    if (len != HD_SIZE) {
        halt("helper data has the wrong size");
    }
}

/*
 * Check the ECDSA P-256 signature of the helper data with the provisioner
 * public key built into the firmware (pk_prov.h). The public key cannot
 * be replaced by rewriting the flash data: it is part of the program.
 */
static void verify_signature(void)
{
    psa_status_t st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        halt_status("crypto init failed", st);
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t key;
    st = psa_import_key(&attr, PK_PROV, sizeof(PK_PROV), &key);
    if (st != PSA_SUCCESS) {
        halt_status("cannot import the public key", st);
    }

    /* SHA-256 of the payload and ECDSA check, in one call. */
    st = psa_verify_message(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                            hd, HD_PAYLOAD,
                            hd + HD_PAYLOAD, HD_SIG);
    psa_destroy_key(key);

    if (st == PSA_ERROR_INVALID_SIGNATURE) {
        halt("bad signature: helper data rejected, nothing decoded");
    }
    if (st != PSA_SUCCESS) {
        halt_status("signature check failed", st);
    }
    printf("Signature OK\n");
}

/*
 * Rebuild the keys: w' = masked cells of the snapshot, corrected with
 * the BCH code and W into w, K_master = SHA-256(w), then K_auth and
 * K_enc derived from K_master. Only the two PSA handles survive.
 */
static void rebuild_key(int cells, int blocks)
{
    uint8_t w[W_MAX_BYTES];
    uint8_t k_master[CRYPTO_SHA256_LEN];
    uint8_t key_id[CRYPTO_KEY_ID_LEN];
    int errs[HD_W_LEN * 8 / FUZZY_N];
    size_t w_bytes = ((size_t)cells + 7) / 8;

    if (w_bytes > sizeof(w) || w_bytes > HD_W_LEN ||
        blocks > (int)(sizeof(errs) / sizeof(errs[0]))) {
        halt("w' does not fit its buffer");
    }
    if (puf_extract(snapshot, &hd[HD_MASK], PUF_SIZE, w, cells) != 0) {
        halt("mask selects fewer cells than expected");
    }

    /* The raw response is no longer needed: do not leave it in RAM. */
    crypto_zeroize(snapshot, sizeof(snapshot));

#if PUF_DEBUG_DUMP
    print_hex("WPRIME", w, w_bytes);
#endif

    /* w' -> w, in place. */
    fuzzy_init();
    int ret = fuzzy_reproduce(w, &hd[HD_W], blocks, errs);

#if PUF_DEBUG_ERRORS
    printf("errors per block:");
    for (int b = 0; b < blocks; b++) {
        printf(" %d", errs[b]);
    }
    printf("\n");
#endif

    if (ret != 0) {
        crypto_zeroize(w, sizeof(w));
        halt("PUF response too noisy: key not rebuilt");
    }

    if (crypto_sha256(w, w_bytes, k_master) != 0) {
        crypto_zeroize(w, sizeof(w));
        halt("SHA-256 failed");
    }
    crypto_zeroize(w, sizeof(w));

    if (crypto_key_id(k_master, key_id) != 0) {
        crypto_zeroize(k_master, sizeof(k_master));
        halt("key id failed");
    }

    psa_status_t st = crypto_derive_keys(k_master, &k_auth, &k_enc);
    crypto_zeroize(k_master, sizeof(k_master));   /* K_master ends here */
    if (st != PSA_SUCCESS) {
        halt_status("key derivation failed", st);
    }

    /* Fingerprint only: it identifies the key without revealing it. */
    print_hex("KEYID", key_id, sizeof(key_id));

    uint8_t tag[8];
    st = crypto_auth_selftest(k_auth, tag);
    if (st != PSA_SUCCESS) {
        halt_status("K_auth self-test failed", st);
    }
    print_hex("AUTHTEST", tag, sizeof(tag));
}

void app_main(void)
{
    /* First instruction: copy the SRAM before anything else writes to it. */
    const volatile uint8_t *p = puf_region();
    for (int i = 0; i < PUF_SIZE; i++) {
        snapshot[i] = p[i];
    }

    load_helper_data();

    /* Signature first: from here on every field can be trusted. */
    verify_signature();

    if (memcmp(hd, "PUFH", 4) != 0) {
        halt("bad magic");
    }

    uint8_t version = hd[4];
    const uint8_t *hd_mac = &hd[5];
    uint32_t hd_addr = le32(&hd[11]);
    uint16_t hd_size = le16(&hd[15]);
    uint8_t n = hd[17], k = hd[18], t = hd[19], blocks = hd[20];

    printf("\nHelper data: %d bytes, version %u\n", HD_SIZE, version);
    printf("  MAC     %02x:%02x:%02x:%02x:%02x:%02x\n",
           hd_mac[0], hd_mac[1], hd_mac[2], hd_mac[3], hd_mac[4], hd_mac[5]);
    printf("  region  0x%08" PRIX32 ", %u bytes\n", hd_addr, hd_size);
    printf("  BCH(%u, %u, t=%u) x%u\n", n, k, t, blocks);

    /* The helper data must belong to this chip. */
    uint8_t my_mac[6];
    esp_efuse_mac_get_default(my_mac);
    if (memcmp(my_mac, hd_mac, 6) != 0) {
        halt("MAC mismatch: helper data of another chip");
    }

    /* The helper data must describe the region this firmware reads. */
    if (hd_addr != PUF_ADDR || hd_size != PUF_SIZE) {
        halt("helper data made for another SRAM region");
    }

    /* The mask must select n * blocks cells. */
    int cells = 0;
    for (int i = 0; i < hd_size; i++) {
        cells += __builtin_popcount(hd[HD_MASK + i]);
    }
    printf("  cells   %d selected\n", cells);
    if (cells != n * blocks) {
        halt("mask does not select n * blocks cells");
    }

    /* The firmware decodes only the code it was built for. */
    if (n != FUZZY_N || k != FUZZY_K || t != FUZZY_T) {
        halt("helper data uses a BCH code this firmware does not support");
    }

    printf("All checks passed.\n\n");

    rebuild_key(cells, blocks);

    /* Network only now: the snapshot is long gone, the WiFi stack may
     * use any RAM it wants. */
    if (net_connect() != 0) {
        halt("network not available");
    }

    /* The device identifies itself by its MAC, as in the helper data. */
    char line[64];
    snprintf(line, sizeof(line), "HELLO %02x%02x%02x%02x%02x%02x",
             my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
    if (net_send_line(line) != 0) {
        halt("send failed");
    }
    printf("sent:     %s\n", line);

    char reply[64];
    if (net_recv_line(reply, sizeof(reply)) < 0) {
        halt("no answer from the server");
    }
    printf("received: %s\n", reply);
    net_close();

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}