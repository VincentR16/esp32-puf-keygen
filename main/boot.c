/*
 * boot.c - Step 1: read the helper data from NVS and check it.
 *
 * No signature and no BCH yet: this only checks that the helper data
 * written from the Mac arrived intact and belongs to this board.
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

#define PUF_ADDR    0x3FFDFC00      /* fixed, same as the measurement firmware */
#define PUF_SIZE    1024            /* SRAM region, bytes */
#define HD_SIZE     1237            /* helper data, bytes */
#define HD_MASK     21              /* offset of the mask */

/* Keep the heap away from the PUF region: nothing will ever write it. */
SOC_RESERVE_MEMORY_REGION(PUF_ADDR, PUF_ADDR + PUF_SIZE, puf_region);

static uint8_t snapshot[PUF_SIZE];
static uint8_t hd[HD_SIZE];

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

void app_main(void)
{
    /* First instruction: copy the SRAM before anything else writes to it. */
    memcpy(snapshot, (const void *)PUF_ADDR, PUF_SIZE);

    load_helper_data();

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

    printf("All checks passed.\n");

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}