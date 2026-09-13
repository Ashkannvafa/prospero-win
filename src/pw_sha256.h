/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * SHA-256 over a byte span.
 *
 * The gate that enters real Wine code must identify the exact bytes it
 * mapped, and the console has no library it can trust for that. This is a
 * small, self-contained implementation of FIPS 180-4 with no allocation and
 * no platform dependency, so host evidence and console evidence use the same
 * code.
 */
#ifndef PROSPERO_WIN_PW_SHA256_H
#define PROSPERO_WIN_PW_SHA256_H

#include <stddef.h>
#include <stdint.h>

enum { PW_SHA256_BYTES = 32, PW_SHA256_HEX_BYTES = 65 };

typedef struct PwSha256 {
    uint32_t state[8];
    uint64_t bits;
    uint8_t buffer[64];
    size_t pending;
} PwSha256;

void pw_sha256_init(PwSha256 *context);
void pw_sha256_update(PwSha256 *context, const void *bytes, size_t size);
void pw_sha256_final(PwSha256 *context, uint8_t digest[PW_SHA256_BYTES]);

/* Lower-case hex plus a terminator; never returns NULL. */
void pw_sha256_hex(const uint8_t digest[PW_SHA256_BYTES],
                   char out[PW_SHA256_HEX_BYTES]);

/* Convenience: hash one span and return its hex form. */
void pw_sha256_hex_span(const void *bytes, size_t size,
                        char out[PW_SHA256_HEX_BYTES]);

#endif
