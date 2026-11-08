#include <string.h>
#include <stdint.h>

#include "headers/sha256.h"

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(e, f, g)  (((e) & (f)) ^ (~(e) & (g)))
#define MAJ(a, b, c) (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define S0(a) (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22))
#define S1(e) (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25))
#define G0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define G1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_compress(uint32_t h[8], const uint8_t *blk)
{
    uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
               ((uint32_t)blk[i * 4 + 2] << 8) | (uint32_t)blk[i * 4 + 3];
    for (; i < 64; i++)
        w[i] = G1(w[i - 2]) + w[i - 7] + G0(w[i - 15]) + w[i - 16];

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (i = 0; i < 64; i++)
    {
        t1 = hh + S1(e) + CH(e, f, g) + K256[i] + w[i];
        t2 = S0(a) + MAJ(a, b, c);
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void sha256_init(sha256_ctx *ctx)
{
    ctx->h[0] = 0x6a09e667; ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372; ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f; ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab; ctx->h[7] = 0x5be0cd19;
    ctx->bits = 0;
    ctx->len = 0;
}

void sha256_update(sha256_ctx *ctx, const uint8_t *data, uint32_t len)
{
    ctx->bits += (uint64_t)len * 8;

    while (len > 0)
    {
        uint32_t cp = 64 - ctx->len;
        if (cp > len)
            cp = len;

        memcpy(ctx->buf + ctx->len, data, cp);
        ctx->len += cp;
        data += cp;
        len -= cp;

        if (ctx->len == 64)
        {
            sha256_compress(ctx->h, ctx->buf);
            ctx->len = 0;
        }
    }
}

void sha256_final(sha256_ctx *ctx, uint8_t *out)
{
    uint64_t bits = ctx->bits;
    uint8_t pad[64] = {0x80};
    uint32_t plen = (ctx->len < 56) ? (56 - ctx->len) : (120 - ctx->len);
    int i;

    sha256_update(ctx, pad, plen);
    for (i = 7; i >= 0; i--)
    {
        uint8_t b = (bits >> (i * 8)) & 0xff;
        sha256_update(ctx, &b, 1);
    }

    for (i = 0; i < 8; i++)
    {
        out[i * 4]     = (uint8_t)(ctx->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->h[i]);
    }
}

void sha256_digest(const uint8_t *data, uint32_t len, uint8_t *out)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}
