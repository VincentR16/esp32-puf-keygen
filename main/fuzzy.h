/*
 * fuzzy.h - Code-offset fuzzy extractor, reconstruction side.
 *
 * BCH(255, 179, t=10) over GF(2^8), primitive polynomial 0x11D.
 * Same algorithm and conventions as host/fuzzy.py:
 *   - block b = bits [255b, 255b + 255) of w (packed MSB first)
 *   - bit i of a block = coefficient of x^i
 *   - systematic code, parity in the 76 low bits
 *
 * Reconstruction:  c' = w' XOR W  ->  BCH decode  ->  error vector e
 *                  w  = c XOR W = w' XOR e
 * so the errors found in c' are flipped directly in w'.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define FUZZY_N  255    /* block length */
#define FUZZY_K  179    /* message bits per block */
#define FUZZY_T  10     /* correctable errors per block */

/* Build the GF(2^8) tables. Call once before fuzzy_reproduce. */
void fuzzy_init(void);

/*
 * Correct w' in place into w.
 *
 *   w       in: w' (blocks * 255 bits, packed MSB first)
 *           out: w, if the function returns 0
 *   W       helper data W, same packing
 *   blocks  number of 255-bit blocks
 *   errs    out: errors corrected in each block (-1 = block not decodable)
 *
 * Returns 0 if every block was decoded, -1 otherwise. On failure w holds
 * no valid key and must be discarded (and zeroized) by the caller.
 */
int fuzzy_reproduce(uint8_t *w, const uint8_t *W, size_t blocks, int *errs);