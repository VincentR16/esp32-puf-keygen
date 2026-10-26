/*
 * puf.h - Select the stable SRAM cells and pack them into w'.
 *
 */

#pragma once

#include <stddef.h>
#include <stdint.h>


int puf_extract(const uint8_t *snapshot, const uint8_t *mask, size_t len,
                uint8_t *out, size_t n_bits);