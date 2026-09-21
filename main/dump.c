#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "esp_system.h"
#include "esp_cpu.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"


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


void app_main(void){

    memcpy(snapshot, puf, PUF_SIZE); //copy the puf to snapshot

    esp_reset_reason_t reason = esp_reset_reason(); //get the reset reason


   unsigned ones = 0;
   for(int i =0; i< PUF_SIZE; i++){
    ones += __builtin_popcount(snapshot[i]); //count the number of ones in the snapshot
   }

   for(uint32_t seq=0; ;seq++){
        printf("\n=== PUF DUMP BEGIN ===\n");
        printf("SEQ %lu\n", (unsigned long)seq);
        printf("UPTIME_MS %lld\n", (long long)(esp_timer_get_time() / 1000));
        printf("RESET_REASON %s\n", reset_reason_str(reason));
        printf("ADDR %p\n", (void *)puf);
        printf("SIZE %d\n", PUF_SIZE);
        printf("ONES %u\n", ones);
        printf("DATA ");

        for (int i =0; i<PUF_SIZE; i++){
            printf("%02X", snapshot[i]);
        }

        printf("\n=== PUF DUMP END ===\n");
 
        vTaskDelay(pdMS_TO_TICKS(2000));

   }

}