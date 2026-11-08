#include <string.h>
#include <stdint.h>

#include "headers/crypto_poly1305.h"

static uint32_t le32_r(const uint8_t *b)
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

void poly1305_mac(uint8_t tag[16], const uint8_t key[32],
                  const uint8_t *msg, int msg_len)
{
    uint8_t r[16];
    uint64_t h0, h1, h2, h3, h4;
    uint64_t r0, r1, r2, r3, r4;
    uint64_t s1, s2, s3, s4;
    uint64_t d0, d1, d2, d3, d4;
    uint64_t c, g0, g1, g2, g3, g4, mask;
    uint64_t f, w0, w1, w2, w3;
    uint8_t blk[17];
    int take;

    memcpy(r, key, 16);
    r[3] &= 15;
    r[4] &= 252;
    r[7] &= 15;
    r[8] &= 252;
    r[11] &= 15;
    r[12] &= 252;
    r[15] &= 15;

    h0 = h1 = h2 = h3 = h4 = 0;
    r0 = le32_r(r) & 0x3ffffff;
    r1 = (le32_r(r + 3) >> 2) & 0x3ffffff;
    r2 = (le32_r(r + 6) >> 4) & 0x3ffffff;
    r3 = (le32_r(r + 9) >> 6) & 0x3ffffff;
    r4 = (le32_r(r + 12) >> 8) & 0x3ffffff;
    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    while (msg_len > 0)
    {
        take = msg_len > 16 ? 16 : msg_len;
        memset(blk, 0, sizeof(blk));
        memcpy(blk, msg, take);
        blk[take] = 1;

        h0 += le32_r(blk) & 0x3ffffff;
        h1 += (le32_r(blk + 3) >> 2) & 0x3ffffff;
        h2 += (le32_r(blk + 6) >> 4) & 0x3ffffff;
        h3 += (le32_r(blk + 9) >> 6) & 0x3ffffff;
        h4 += (le32_r(blk + 12) >> 8) & 0x3ffffff;
        h4 += (uint64_t)blk[16] << 24;

        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;
        c = h1 >> 26;
        h1 &= 0x3ffffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x3ffffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x3ffffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x3ffffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;

        d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        c = d0 >> 26;
        d0 &= 0x3ffffff;
        d1 += c;
        c = d1 >> 26;
        d1 &= 0x3ffffff;
        d2 += c;
        c = d2 >> 26;
        d2 &= 0x3ffffff;
        d3 += c;
        c = d3 >> 26;
        d3 &= 0x3ffffff;
        d4 += c;
        c = d4 >> 26;
        d4 &= 0x3ffffff;
        d0 += c * 5;
        c = d0 >> 26;
        d0 &= 0x3ffffff;
        d1 += c;

        h0 = d0;
        h1 = d1;
        h2 = d2;
        h3 = d3;
        h4 = d4;
        msg += take;
        msg_len -= take;
    }

    c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    g0 = h0 + 5;
    g1 = h1 + (g0 >> 26);
    g0 &= 0x3ffffff;
    g2 = h2 + (g1 >> 26);
    g1 &= 0x3ffffff;
    g3 = h3 + (g2 >> 26);
    g2 &= 0x3ffffff;
    g4 = h4 + (g3 >> 26);
    g3 &= 0x3ffffff;
    mask = (uint64_t)(-(g4 >> 26));
    g4 &= 0x3ffffff;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    h0 += le32_r(key + 16) & 0x3ffffff;
    h1 += (le32_r(key + 19) >> 2) & 0x3ffffff;
    h2 += (le32_r(key + 22) >> 4) & 0x3ffffff;
    h3 += (le32_r(key + 25) >> 6) & 0x3ffffff;
    h4 += (le32_r(key + 28) >> 8) & 0x3ffffff;

    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;
    c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;

    w0 = h0 | (h1 << 26);
    w1 = (h1 >> 6) | (h2 << 20);
    w2 = (h2 >> 12) | (h3 << 14);
    w3 = (h3 >> 18) | (h4 << 8);
    f = w0;
    tag[0] = (uint8_t)f;
    tag[1] = (uint8_t)(f >> 8);
    tag[2] = (uint8_t)(f >> 16);
    tag[3] = (uint8_t)(f >> 24);
    f >>= 32;
    f += w1 + le32_r(key + 20);
    tag[4] = (uint8_t)f;
    tag[5] = (uint8_t)(f >> 8);
    tag[6] = (uint8_t)(f >> 16);
    tag[7] = (uint8_t)(f >> 24);
    f >>= 32;
    f += w2 + le32_r(key + 24);
    tag[8] = (uint8_t)f;
    tag[9] = (uint8_t)(f >> 8);
    tag[10] = (uint8_t)(f >> 16);
    tag[11] = (uint8_t)(f >> 24);
    f >>= 32;
    f += w3 + le32_r(key + 28);
    tag[12] = (uint8_t)f;
    tag[13] = (uint8_t)(f >> 8);
    tag[14] = (uint8_t)(f >> 16);
    tag[15] = (uint8_t)(f >> 24);
}
