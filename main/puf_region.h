// main/puf_region.h

#ifndef PUF_REGION_H
#define PUF_REGION_H

#include <stdint.h>
#include <stddef.h>

// Region of the SRAM for the PUF.

#define PUF_ADDR 0x3FFDFC00UL
#define PUF_SIZE 1024U

static inline volatile uint8_t *puf_region(void)
{
    return (volatile uint8_t *)PUF_ADDR;
}

#endif // PUF_REGION_H