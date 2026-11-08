#pragma once

#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint8_t  buf[64];
    uint64_t bits;
    uint32_t len;
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, uint32_t len);
void sha256_final(sha256_ctx *ctx, uint8_t *out);
void sha256_digest(const uint8_t *data, uint32_t len, uint8_t *out);
