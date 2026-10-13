/*
 * puf.c - Select the stable SRAM cells and pack them into w'.
 * See puf.h for the bit conventions.
 */

#include <string.h>

#include "puf.h"

int puf_extract(const uint8_t *snapshot, const uint8_t *mask, size_t len,
                uint8_t *out, size_t n_bits)
{
    memset(out, 0, (n_bits + 7) / 8);   /* also gives the zero padding */

    size_t j = 0;                       /* next bit of w' to write */
    for (size_t i = 0; i < len * 8 && j < n_bits; i++) {
        uint8_t sel = 0x80 >> (i % 8);  /* bit i of the region, MSB first */
        if (mask[i / 8] & sel) {
            if (snapshot[i / 8] & sel) {
                out[j / 8] |= 0x80 >> (j % 8);
            }
            j++;
        }
    }
    return (j == n_bits) ? 0 : -1;
}