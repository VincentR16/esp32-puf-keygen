#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "esp_system.h"
#include "esp_cpu.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


#define PUF_SIZE 1024

static uint8_t puf[PUF_SIZE] __attribute__((section(".noinit"))); 
static uint8_t snapshot[PUF_SIZE]; //copy of the puf for not modifying the original one

static const char *reset_reason_str(esp_reset_reason_t r) //the type come from esp_system.h
{
    switch (r) {
        case ESP_RST_POWERON:  return "POWERON";   // the only valid state for the PUF 
        case ESP_RST_SW:       return "SW";
        case ESP_RST_PANIC:    return "PANIC";
        case ESP_RST_INT_WDT:  return "INT_WDT";
        case ESP_RST_TASK_WDT: return "TASK_WDT";
        case ESP_RST_WDT:      return "WDT";
        case ESP_RST_DEEPSLEEP:return "DEEPSLEEP";
        case ESP_RST_BROWNOUT: return "BROWNOUT";
        case ESP_RST_SDIO:     return "SDIO";
        case ESP_RST_EXT:      return "EXT";
        default:               return "UNKNOWN";
    }
}

static void print_stats(const uint8_t *buf, size_t len)
{
    size_t ones = 0, zeros = 0, ff_bytes = 0;

    for (size_t i=0; i<len ; i++){
        if (buf[i]== 0x00) zeros++;
        else if (buf[i]== 0xff) ff_bytes++;
        else ones = __builtin_popcount(buf[i]);  //count the number of 1 bits in the byte
    }

     printf("STATS ones=%u/%u (%.2f%%) zero_bytes=%u ff_bytes=%u\n",
           (unsigned)ones, (unsigned)(len * 8),
           100.0 * ones / (len * 8),
           (unsigned)zeros, (unsigned)ff_bytes);
}

void app_main(void){

    memcpy(snapshot, puf, PUF_SIZE); //copy the puf to snapshot

    esp_reset_reason_t reason = esp_reset_reason(); //get the reset reason

    vTaskDelay(pdMS_TO_TICKS(500)); //wait for 1 second

    printf("\n");
    printf("=== PUF DUMP BEGIN ===\n");
    printf("RESET_REASON %s\n", reset_reason_str(reason));
    printf("ADDR %p\n", (void *)puf);
    printf("SIZE %d\n", PUF_SIZE);

    print_stats(snapshot, PUF_SIZE);

     printf("DATA ");
    for (int i = 0; i < PUF_SIZE; i++) {
        printf("%02x", snapshot[i]);
    }
    printf("\n");
    printf("=== PUF DUMP END ===\n");
 
    /* Nessun restart automatico: il riavvio lo controlli tu,
     * staccando l'alimentazione. */
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

}