/*
 * dump.c - Read the PUF region at a fixed address (measurement firmware).
 *
 * The region no longer depends on the size of the firmware: it sits at a
 * fixed address, far from the program data, and the heap is told never to
 * use it. The snapshot is taken once at boot and printed every 2 s, so
 * host/collect.py can catch it.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "heap_memory_layout.h"

#define PUF_ADDR 0x3FFDFC00     /* last KB of the main DRAM region */
#define PUF_SIZE 1024

/* Keep the heap away from the PUF region: nothing will ever write it. */
SOC_RESERVE_MEMORY_REGION(PUF_ADDR, PUF_ADDR + PUF_SIZE, puf_region);

static uint8_t snapshot[PUF_SIZE];

static const char *reset_reason_str(esp_reset_reason_t r)
{
    switch (r) {
    case ESP_RST_POWERON: return "POWERON";
    case ESP_RST_EXT:     return "EXT";
    case ESP_RST_SW:      return "SW";
    case ESP_RST_PANIC:   return "PANIC";
    case ESP_RST_INT_WDT: return "INT_WDT";
    case ESP_RST_TASK_WDT:return "TASK_WDT";
    case ESP_RST_WDT:     return "WDT";
    case ESP_RST_BROWNOUT:return "BROWNOUT";
    default:              return "OTHER";
    }
}

void app_main(void)
{
    /* First instruction: copy the region before anything else runs. */
    memcpy(snapshot, (const void *)PUF_ADDR, PUF_SIZE);

    esp_reset_reason_t reason = esp_reset_reason();

    unsigned ones = 0;
    for (int i = 0; i < PUF_SIZE; i++) {
        ones += __builtin_popcount(snapshot[i]);
    }

    for (uint32_t seq = 0; ; seq++) {
        printf("\n=== PUF DUMP BEGIN ===\n");
        printf("SEQ %lu\n", (unsigned long)seq);
        printf("UPTIME_MS %lld\n", (long long)(esp_timer_get_time() / 1000));
        printf("RESET_REASON %s\n", reset_reason_str(reason));
        printf("ADDR 0x%08X\n", PUF_ADDR);
        printf("SIZE %d\n", PUF_SIZE);
        printf("ONES %u\n", ones);
        printf("DATA ");
        for (int i = 0; i < PUF_SIZE; i++) {
            printf("%02x", snapshot[i]);
        }
        printf("\n=== PUF DUMP END ===\n");

        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}