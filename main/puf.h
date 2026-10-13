/*
 * puf.h - Select the stable SRAM cells and pack them into w'.
 *
 * Bit conventions (identical to host/fuzzy.py):
 *   - bit i of a buffer = byte i/8, position 7 - (i % 8)  (MSB first)
 *   - the cells are the bits set to 1 in the mask, in address order
 *   - w' is packed MSB first; the bits after the last cell are 0
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Copy into out the snapshot bits selected by the mask.
 *
 *   snapshot  raw SRAM power-up content, len bytes
 *   mask      enrollment mask, len bytes (1 = cell used for the key)
 *   out       (n_bits + 7) / 8 bytes, fully overwritten
 *   n_bits    number of cells to take (n * blocks)
 *
 * Returns 0 on success, -1 if the mask selects fewer than n_bits cells.
 */
int puf_extract(const uint8_t *snapshot, const uint8_t *mask, size_t len,
                uint8_t *out, size_t n_bits);