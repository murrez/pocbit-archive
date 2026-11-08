#include <stdlib.h>
#include <string.h>
#include "encrypt.h"
#include "rand.h"

static uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

static uint32_t load_le32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
}

void chacha20_init(uint32_t state[16], const uint8_t key[32], uint32_t counter, const uint8_t nonce[12])
{
    const uint8_t *sigma = (const uint8_t *)"expand 32-byte k";
    state[0] = load_le32(sigma);
    state[1] = load_le32(sigma + 4);
    state[2] = load_le32(sigma + 8);
    state[3] = load_le32(sigma + 12);
    for (int i = 0; i < 8; i++)
        state[4 + i] = load_le32(key + i * 4);
    state[12] = counter;
    state[13] = load_le32(nonce);
    state[14] = load_le32(nonce + 4);
    state[15] = load_le32(nonce + 8);
}

void chacha20_block(uint32_t state[16], uint8_t out[64])
{
    uint32_t ws[16];
    memcpy(ws, state, 64);
    for (int i = 0; i < 10; i++)
    {
        quarter_round(&ws[0], &ws[4], &ws[8], &ws[12]);
        quarter_round(&ws[1], &ws[5], &ws[9], &ws[13]);
        quarter_round(&ws[2], &ws[6], &ws[10], &ws[14]);
        quarter_round(&ws[3], &ws[7], &ws[11], &ws[15]);
        quarter_round(&ws[0], &ws[5], &ws[10], &ws[15]);
        quarter_round(&ws[1], &ws[6], &ws[11], &ws[12]);
        quarter_round(&ws[2], &ws[7], &ws[8], &ws[13]);
        quarter_round(&ws[3], &ws[4], &ws[9], &ws[14]);
    }
    for (int i = 0; i < 16; i++)
    {
        ws[i] += state[i];
        memcpy(out + i * 4, &ws[i], 4);
    }
}

void chacha20_encrypt(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], const uint8_t *in, uint8_t *out, int len)
{
    uint32_t state[16];
    chacha20_init(state, key, counter, nonce);
    uint8_t keystream[64];
    int off = 0;
    while (len > 0)
    {
        chacha20_block(state, keystream);
        int chunk = len > 64 ? 64 : len;
        for (int i = 0; i < chunk; i++) out[off + i] = in[off + i] ^ keystream[i];
        off += chunk;
        len -= chunk;
        state[12]++;
    }
}

static uint32_t le32_r(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
}

void poly1305_mac(uint8_t tag[16], const uint8_t key[32], const uint8_t *msg, int msg_len)
{
    uint8_t r[16];
    memcpy(r, key, 16);
    r[3] &= 15; r[4] &= 252; r[7] &= 15; r[8] &= 252; r[11] &= 15; r[12] &= 252; r[15] &= 15;

    uint64_t h0=0, h1=0, h2=0, h3=0, h4=0;
    uint64_t r0 = le32_r(r) & 0x3FFFFFF;
    uint64_t r1 = (le32_r(r+3) >> 2) & 0x3FFFFFF;
    uint64_t r2 = (le32_r(r+6) >> 4) & 0x3FFFFFF;
    uint64_t r3 = (le32_r(r+9) >> 6) & 0x3FFFFFF;
    uint64_t r4 = (le32_r(r+12) >> 8) & 0x3FFFFFF;

    while (msg_len > 0) {
        int take = msg_len > 16 ? 16 : msg_len;
        uint8_t blk[17] = {0};
        memcpy(blk, msg, take);
        blk[take] = 1;

        h0 += le32_r(blk) & 0x3FFFFFF;
        h1 += (le32_r(blk+3) >> 2) & 0x3FFFFFF;
        h2 += (le32_r(blk+6) >> 4) & 0x3FFFFFF;
        h3 += (le32_r(blk+9) >> 6) & 0x3FFFFFF;
        h4 += (le32_r(blk+12) >> 8) & 0x3FFFFFF;
        h4 += (uint64_t)blk[16] << 24;

        { uint64_t c;
          c = h0 >> 26; h0 &= 0x3FFFFFF; h1 += c;
          c = h1 >> 26; h1 &= 0x3FFFFFF; h2 += c;
          c = h2 >> 26; h2 &= 0x3FFFFFF; h3 += c;
          c = h3 >> 26; h3 &= 0x3FFFFFF; h4 += c;
          c = h4 >> 26; h4 &= 0x3FFFFFF; h0 += c * 5;
          c = h0 >> 26; h0 &= 0x3FFFFFF; h1 += c; }

        uint64_t d0 = h0*r0 + h1*r4*5 + h2*r3*5 + h3*r2*5 + h4*r1*5;
        uint64_t d1 = h0*r1 + h1*r0 + h2*r4*5 + h3*r3*5 + h4*r2*5;
        uint64_t d2 = h0*r2 + h1*r1 + h2*r0 + h3*r4*5 + h4*r3*5;
        uint64_t d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*r4*5;
        uint64_t d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

        { uint64_t c;
          c = d0 >> 26; d0 &= 0x3FFFFFF; d1 += c;
          c = d1 >> 26; d1 &= 0x3FFFFFF; d2 += c;
          c = d2 >> 26; d2 &= 0x3FFFFFF; d3 += c;
          c = d3 >> 26; d3 &= 0x3FFFFFF; d4 += c;
          c = d4 >> 26; d4 &= 0x3FFFFFF; d0 += c * 5;
          c = d0 >> 26; d0 &= 0x3FFFFFF; d1 += c; }

        h0 = d0; h1 = d1; h2 = d2; h3 = d3; h4 = d4;
        msg += take; msg_len -= take;
    }

    /* Final conditional reduction mod 2^130-5 */
    { uint64_t g0, g1, g2, g3, g4, mask;
      g0 = h0 + 5;
      g1 = h1 + (g0 >> 26); g0 &= 0x3FFFFFF;
      g2 = h2 + (g1 >> 26); g1 &= 0x3FFFFFF;
      g3 = h3 + (g2 >> 26); g2 &= 0x3FFFFFF;
      g4 = h4 + (g3 >> 26); g3 &= 0x3FFFFFF;
      mask = (uint64_t)(-(g4 >> 26)); /* 0xFFFF... if h >= p, 0 otherwise */
      g4 &= 0x3FFFFFF;
      h0 = (h0 & ~mask) | (g0 & mask);
      h1 = (h1 & ~mask) | (g1 & mask);
      h2 = (h2 & ~mask) | (g2 & mask);
      h3 = (h3 & ~mask) | (g3 & mask);
      h4 = (h4 & ~mask) | (g4 & mask); }

    /* Add s (second half of key) */
    h0 += le32_r(key+16) & 0x3FFFFFF;
    h1 += (le32_r(key+19) >> 2) & 0x3FFFFFF;
    h2 += (le32_r(key+22) >> 4) & 0x3FFFFFF;
    h3 += (le32_r(key+25) >> 6) & 0x3FFFFFF;
    h4 += (le32_r(key+28) >> 8) & 0x3FFFFFF;

    { uint64_t c;
      c = h0 >> 26; h0 &= 0x3FFFFFF; h1 += c;
      c = h1 >> 26; h1 &= 0x3FFFFFF; h2 += c;
      c = h2 >> 26; h2 &= 0x3FFFFFF; h3 += c;
      c = h3 >> 26; h3 &= 0x3FFFFFF; h4 += c; }

    uint64_t w0 = h0 | (h1 << 26);
    uint64_t w1 = (h1 >> 6) | (h2 << 20);
    uint64_t w2 = (h2 >> 12) | (h3 << 14);
    uint64_t w3 = (h3 >> 18) | (h4 << 8);
    memcpy(tag, &w0, 4); memcpy(tag+4, &w1, 4);
    memcpy(tag+8, &w2, 4); memcpy(tag+12, &w3, 4);
}

static uint8_t nonce_prefix[4] = {0};

void set_nonce_prefix(const uint8_t prefix[4]) {
    memcpy(nonce_prefix, prefix, 4);
}

int encrypt_packet(const uint8_t key[32], uint32_t seq, const uint8_t *plain, int plain_len, uint8_t *out, int *out_len)
{
    uint8_t nonce[12] = {0};
    nonce[8]  = (seq >> 24) & 0xff;
    nonce[9]  = (seq >> 16) & 0xff;
    nonce[10] = (seq >>  8) & 0xff;
    nonce[11] =  seq        & 0xff;

    /* OTK = ChaCha20(key, counter=0, nonce) XOR key — matches CNC's c.XORKeyStream(otk, key) */
    uint8_t otk[32];
    chacha20_encrypt(key, 0, nonce, key, otk, 32);
    chacha20_encrypt(key, 1, nonce, plain, out, plain_len);
    poly1305_mac(out + plain_len, otk, out, plain_len);
    *out_len = plain_len + 16;
    return 0;
}

int decrypt_packet(const uint8_t key[32], uint32_t seq, const uint8_t *in, int in_len, uint8_t *plain, int *plain_len)
{
    if (in_len < 16) return -1;
    int cipher_len = in_len - 16;

    uint8_t nonce[12] = {0};
    nonce[8]  = (seq >> 24) & 0xff;
    nonce[9]  = (seq >> 16) & 0xff;
    nonce[10] = (seq >>  8) & 0xff;
    nonce[11] =  seq        & 0xff;

    /* OTK = ChaCha20(key, counter=0, nonce) XOR key — matches CNC's c.XORKeyStream(otk, key) */
    uint8_t otk[32];
    chacha20_encrypt(key, 0, nonce, key, otk, 32);

    uint8_t expected_tag[16];
    poly1305_mac(expected_tag, otk, in, cipher_len);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= in[cipher_len + i] ^ expected_tag[i];
    if (diff != 0) return -1;

    chacha20_encrypt(key, 1, nonce, in, plain, cipher_len);
    *plain_len = cipher_len;
    return 0;
}
