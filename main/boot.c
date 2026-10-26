/*
 * boot.c - Read the helper data from NVS, check its signature and its
 * consistency with this board, then rebuild the keystravel as hex. The server answers DENIED on failure.
 */

#include <ctype.h>
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
#include "display.h"
#include "fuzzy.h"
#include "net.h"
#include "pk_prov.h"
#include "puf.h"
#include "puf_region.h"
#include "sensor.h"

#define HD_SIZE     1237            /* helper data, bytes */
#define HD_SIG      64              /* ECDSA signature */
#define HD_PAYLOAD  (HD_SIZE - HD_SIG)  /* bytes covered by the signature */
#define HD_MASK     21              /* offset of the mask */
#define HD_W        1045            /* offset of W */
#define HD_W_LEN    128             /* bytes of W */

#define W_MAX_BYTES 128             /* room for w' (1020 bits + padding) */

#define DATA_PERIOD_MS   20000      /* one reading every 20 s */
#define SENSOR_TRIES     3          /* attempts per reading */
#define SENSOR_RETRY_MS  1500       /* DHT11: at least 1 s between reads */


SOC_RESERVE_MEMORY_REGION(PUF_ADDR, PUF_ADDR + PUF_SIZE, puf_reserved);

static uint8_t snapshot[PUF_SIZE];
static uint8_t hd[HD_SIZE];


static psa_key_id_t k_auth;
static psa_key_id_t k_enc;

/* Nonces of the handshake: the session key will be derived from them. */
static uint8_t ns[CRYPTO_NONCE_LEN];
static uint8_t nd[CRYPTO_NONCE_LEN];

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

static void load_helper_data(void)
{

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


static void rebuild_key(int cells, int blocks)
{
    uint8_t w[W_MAX_BYTES];
    uint8_t k_master[CRYPTO_SHA256_LEN];
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


    fuzzy_init();
    int ret = fuzzy_reproduce(w, &hd[HD_W], blocks, errs);

    if (ret != 0) {
        crypto_zeroize(w, sizeof(w));
        halt("PUF response too noisy: key not rebuilt");
    }

    if (crypto_sha256(w, w_bytes, k_master) != 0) {
        crypto_zeroize(w, sizeof(w));
        halt("SHA-256 failed");
    }
    crypto_zeroize(w, sizeof(w));

    psa_status_t st = crypto_derive_keys(k_master, &k_auth, &k_enc);
    crypto_zeroize(k_master, sizeof(k_master));   /* K_master ends here */
    if (st != PSA_SUCCESS) {
        halt_status("key derivation failed", st);
    }
    printf("Key rebuilt.\n");
}



static void to_hex(const uint8_t *in, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(out + 2 * i, "%02x", in[i]);
    }
}


static int from_hex(const char *in, uint8_t *out, size_t len)
{
    if (strlen(in) != 2 * len) {
        return -1;
    }
    for (size_t i = 0; i < 2 * len; i++) {
        if (!isxdigit((unsigned char)in[i])) {
            return -1;
        }
    }
    for (size_t i = 0; i < len; i++) {
        sscanf(in + 2 * i, "%2hhx", &out[i]);
    }
    return 0;
}

static void send_line(const char *line)
{
    if (net_send_line(line) != 0) {
        halt("send failed");
    }
}

static void recv_line(char *line, size_t len)
{
    if (net_recv_line(line, len) < 0) {
        halt("no answer from the server");
    }
    if (strcmp(line, "DENIED") == 0) {
        halt("server DENIED: it does not recognize this chip's key");
    }
}

static void authenticate(const uint8_t id[CRYPTO_ID_LEN])
{
    char line[160];
    char hex_a[2 * CRYPTO_TAG_LEN + 1];
    char hex_b[2 * CRYPTO_TAG_LEN + 1];
    uint8_t tag[CRYPTO_TAG_LEN];

    /* 1. HELLO <id> */
    to_hex(id, CRYPTO_ID_LEN, hex_a);
    snprintf(line, sizeof(line), "HELLO %s", hex_a);
    send_line(line);

    /* 2. NONCE <N_s> */
    recv_line(line, sizeof(line));
    if (strncmp(line, "NONCE ", 6) != 0 ||
        from_hex(line + 6, ns, CRYPTO_NONCE_LEN) != 0) {
        halt("expected NONCE");
    }

    if (crypto_random(nd, CRYPTO_NONCE_LEN) != PSA_SUCCESS ||
        crypto_auth_tag(k_auth, CRYPTO_ROLE_DEV, ns, nd, id, tag) != PSA_SUCCESS) {
        halt("cannot compute the device tag");
    }
    to_hex(nd, CRYPTO_NONCE_LEN, hex_a);
    to_hex(tag, CRYPTO_TAG_LEN, hex_b);
    snprintf(line, sizeof(line), "AUTH %s %s", hex_a, hex_b);
    send_line(line);

    recv_line(line, sizeof(line));
    if (strncmp(line, "SERVER ", 7) != 0 ||
        from_hex(line + 7, tag, CRYPTO_TAG_LEN) != 0) {
        halt("expected SERVER");
    }
    if (crypto_auth_verify(k_auth, CRYPTO_ROLE_SRV, ns, nd, id, tag) != PSA_SUCCESS) {
        halt("server tag INVALID: not the real server");
    }
    printf("\nAuthentication OK: device and server share K_auth.\n");
}

static int read_sensor(int *temp10, int *hum)
{
    int err = 0;
    for (int i = 1; i <= SENSOR_TRIES; i++) {
        err = sensor_read(temp10, hum);
        if (err == 0) {
            return 0;
        }
        printf("sensor read failed (%d), attempt %d/%d\n", err, i, SENSOR_TRIES);
        if (i < SENSOR_TRIES) {
            vTaskDelay(pdMS_TO_TICKS(SENSOR_RETRY_MS));
        }
    }
    return err;
}


static void send_data(const uint8_t id[CRYPTO_ID_LEN])
{
    psa_key_id_t k_sess;
    if (crypto_session_key(k_enc, ns, nd, &k_sess) != PSA_SUCCESS) {
        halt("cannot derive the session key");
    }
    printf("Session key derived.\n\n");

    /* seq is the GCM nonce: it starts at 1, grows only when a message
     * is sent, and never repeats. */
    uint32_t seq = 1;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(DATA_PERIOD_MS));

        int temp10, hum;
        if (read_sensor(&temp10, &hum) != 0) {
            printf("no valid reading: message skipped\n");
            continue;                       /* nothing sent, seq unchanged */
        }

        display_show(temp10, hum);

        char pt[32];
        snprintf(pt, sizeof(pt), "%d.%d,%d", temp10 / 10, temp10 % 10, hum);

        uint8_t ct[sizeof(pt) + CRYPTO_GCM_TAG_LEN];
        size_t ct_len = 0;
        if (crypto_seal(k_sess, id, seq, (const uint8_t *)pt, strlen(pt),
                        ct, sizeof(ct), &ct_len) != PSA_SUCCESS) {
            halt("encryption failed");
        }

        char hex[2 * sizeof(ct) + 1];
        char line[200];
        to_hex(ct, ct_len, hex);
        snprintf(line, sizeof(line), "DATA %08" PRIx32 " %s", seq, hex);
        send_line(line);

        if (++seq == 0) {
            halt("sequence number exhausted");   /* after 2^32 - 1 messages */
        }
    }
}

void app_main(void)
{
    const volatile uint8_t *p = puf_region();
    for (int i = 0; i < PUF_SIZE; i++) {
        snapshot[i] = p[i];
    }

    load_helper_data();

    verify_signature();

    if (memcmp(hd, "PUFH", 4) != 0) {
        halt("bad magic");
    }

    const uint8_t *hd_mac = &hd[5];
    uint32_t hd_addr = le32(&hd[11]);
    uint16_t hd_size = le16(&hd[15]);
    uint8_t n = hd[17], k = hd[18], t = hd[19], blocks = hd[20];

    uint8_t my_mac[6];
    esp_efuse_mac_get_default(my_mac);
    if (memcmp(my_mac, hd_mac, 6) != 0) {
        halt("MAC mismatch: helper data of another chip");
    }

    if (hd_addr != PUF_ADDR || hd_size != PUF_SIZE) {
        halt("helper data made for another SRAM region");
    }

    int cells = 0;
    for (int i = 0; i < hd_size; i++) {
        cells += __builtin_popcount(hd[HD_MASK + i]);
    }
    if (cells != n * blocks) {
        halt("mask does not select n * blocks cells");
    }

    if (n != FUZZY_N || k != FUZZY_K || t != FUZZY_T) {
        halt("helper data uses a BCH code this firmware does not support");
    }

    printf("All checks passed.\n");

    rebuild_key(cells, blocks);

    if (sensor_init() != 0) {
        halt("sensor init failed");
    }
    if (display_init() != 0) {
        printf("display not available, continuing without it\n");
    }

    /* Network only now: the snapshot is long gone, the WiFi stack may
     * use any RAM it wants. */
    if (net_connect() != 0) {
        halt("network not available");
    }

    authenticate(my_mac);
    send_data(my_mac);                       /* does not return */

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}