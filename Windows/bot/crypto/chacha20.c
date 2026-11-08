#include "chacha20.h"
#include <string.h>

/* 1:1 port of pkg/chacha20 in quantumv3 (IETF 12-byte nonce, 32-bit counter). */

static void u32t8le(uint32_t v, uint8_t *p) {
    p[0] = v & 0xFF;
    p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF;
    p[3] = (v >> 24) & 0xFF;
}

static uint32_t u8t32le(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void qround(uint32_t x[16], int a, int b, int c, int d) {
    x[a] += x[b];
    x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d];
    x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b];
    x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] += x[d];
    x[b] = rotl32(x[b] ^ x[c], 7);
}

static void serialize(const uint32_t in[16], uint8_t *out) {
    int i;
    for (i = 0; i < 16; i++) u32t8le(in[i], out + i * 4);
}

static void block(const uint32_t in[16], uint8_t *out, int rounds) {
    uint32_t x[16];
    int i;
    memcpy(x, in, sizeof x);

    for (i = rounds; i > 0; i -= 2) {
        qround(x, 0, 4, 8, 12);
        qround(x, 1, 5, 9, 13);
        qround(x, 2, 6, 10, 14);
        qround(x, 3, 7, 11, 15);
        qround(x, 0, 5, 10, 15);
        qround(x, 1, 6, 11, 12);
        qround(x, 2, 7, 8, 13);
        qround(x, 3, 4, 9, 14);
    }

    for (i = 0; i < 16; i++) x[i] += in[i];
    serialize(x, out);
}

static void init_state(uint32_t s[16], const uint8_t *key, uint32_t counter,
                       const uint8_t *nonce) {
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;

    int i;
    for (i = 0; i < 8; i++) s[4 + i] = u8t32le(key + i * 4);

    s[12] = counter;
    for (i = 0; i < 3; i++) s[13 + i] = u8t32le(nonce + i * 4);
}

void chacha20_xor(const uint8_t *key, uint32_t counter, const uint8_t *nonce,
                  const uint8_t *in, uint8_t *out, size_t len) {
    uint32_t s[16];
    uint8_t blk[64];
    size_t i, j;
    size_t off = 0;

    init_state(s, key, counter, nonce);

    for (i = 0; i < len; i += 64) {
        block(s, blk, 20);
        s[12]++;
        for (j = i; j < i + 64 && j < len; j++) {
            out[j] = in[j] ^ blk[j - i];
        }
    }
    (void)off;
}

void chacha20_encrypt(const uint8_t *key, uint32_t counter, const uint8_t *nonce,
                      const uint8_t *in, uint8_t *out, size_t len) {
    memcpy(out, in, len);
    chacha20_xor(key, counter, nonce, in, out, len);
}
