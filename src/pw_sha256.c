/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_sha256.h"

#include <string.h>

static const uint32_t k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static uint32_t rotate_right(uint32_t value, unsigned bits)
{
    return (value >> bits) | (value << (32u - bits));
}

static void compress(PwSha256 *context, const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (unsigned index = 0; index < 16u; ++index)
        w[index] = ((uint32_t)block[index * 4u] << 24) |
                   ((uint32_t)block[index * 4u + 1u] << 16) |
                   ((uint32_t)block[index * 4u + 2u] << 8) |
                   (uint32_t)block[index * 4u + 3u];
    for (unsigned index = 16u; index < 64u; ++index) {
        const uint32_t s0 = rotate_right(w[index - 15u], 7) ^
                            rotate_right(w[index - 15u], 18) ^
                            (w[index - 15u] >> 3);
        const uint32_t s1 = rotate_right(w[index - 2u], 17) ^
                            rotate_right(w[index - 2u], 19) ^
                            (w[index - 2u] >> 10);

        w[index] = w[index - 16u] + s0 + w[index - 7u] + s1;
    }
    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];
    for (unsigned index = 0; index < 64u; ++index) {
        const uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^
                            rotate_right(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t temp1 = h + s1 + ch + k[index] + w[index];
        const uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^
                            rotate_right(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

void pw_sha256_init(PwSha256 *context)
{
    static const uint32_t initial[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };

    if (!context)
        return;
    memcpy(context->state, initial, sizeof(initial));
    context->bits = 0u;
    context->pending = 0u;
}

void pw_sha256_update(PwSha256 *context, const void *bytes, size_t size)
{
    const uint8_t *input = bytes;

    if (!context || (!input && size != 0u))
        return;
    context->bits += (uint64_t)size * 8u;
    while (size != 0u) {
        const size_t space = sizeof(context->buffer) - context->pending;
        const size_t take = size < space ? size : space;

        memcpy(context->buffer + context->pending, input, take);
        context->pending += take;
        input += take;
        size -= take;
        if (context->pending == sizeof(context->buffer)) {
            compress(context, context->buffer);
            context->pending = 0u;
        }
    }
}

void pw_sha256_final(PwSha256 *context, uint8_t digest[PW_SHA256_BYTES])
{
    static const uint8_t zeros[64] = {0};
    static const uint8_t marker = 0x80u;
    uint8_t length[8];
    uint64_t bits;
    size_t padding;

    if (!context || !digest)
        return;
    bits = context->bits;
    /* 0x80, then zeros until the block has exactly eight bytes left. */
    padding = context->pending < 56u ? 56u - context->pending
                                     : 120u - context->pending;
    pw_sha256_update(context, &marker, 1u);
    if (padding > 1u)
        pw_sha256_update(context, zeros, padding - 1u);
    for (unsigned index = 0; index < 8u; ++index)
        length[index] = (uint8_t)(bits >> (56u - index * 8u));
    pw_sha256_update(context, length, 8u);
    for (unsigned index = 0; index < 8u; ++index) {
        digest[index * 4u] = (uint8_t)(context->state[index] >> 24);
        digest[index * 4u + 1u] = (uint8_t)(context->state[index] >> 16);
        digest[index * 4u + 2u] = (uint8_t)(context->state[index] >> 8);
        digest[index * 4u + 3u] = (uint8_t)context->state[index];
    }
}

void pw_sha256_hex(const uint8_t digest[PW_SHA256_BYTES],
                   char out[PW_SHA256_HEX_BYTES])
{
    static const char digits[] = "0123456789abcdef";

    if (!out)
        return;
    for (unsigned index = 0; index < PW_SHA256_BYTES; ++index) {
        const uint8_t byte = digest ? digest[index] : 0u;

        out[index * 2u] = digits[byte >> 4];
        out[index * 2u + 1u] = digits[byte & 0x0fu];
    }
    out[PW_SHA256_BYTES * 2u] = '\0';
}

void pw_sha256_hex_span(const void *bytes, size_t size,
                        char out[PW_SHA256_HEX_BYTES])
{
    PwSha256 context;
    uint8_t digest[PW_SHA256_BYTES];

    pw_sha256_init(&context);
    pw_sha256_update(&context, bytes, size);
    pw_sha256_final(&context, digest);
    pw_sha256_hex(digest, out);
}
