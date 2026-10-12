// main/puf_region.h

#ifndef PUF_REGION_H
#define PUF_REGION_H

#include <stdint.h>

// SRAM region used as PUF. Fixed address, reserved from the heap with
// SOC_RESERVE_MEMORY_REGION in the .c file of each firmware.
#define PUF_ADDR 0x3FFDFC00U
#define PUF_SIZE 1024U

// Read-only view of the region: the firmware must never write to it.
static inline const volatile uint8_t *puf_region(void)
{
    return (const volatile uint8_t *)PUF_ADDR;
}

#endif // PUF_REGION_H