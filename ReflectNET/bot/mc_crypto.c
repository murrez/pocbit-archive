#include <string.h>
#include <stdint.h>

#include "headers/mc_crypto.h"
#include "headers/rand.h"
#include "headers/util.h"

/* ─── AES-128 (ECB block) for CFB8 ─── */

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rcon[11] = {0,1,2,4,8,16,32,64,128,27,54};

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

static void aes128_key_expand(const uint8_t key[16], uint8_t rk[176])
{
    int i;
    memcpy(rk, key, 16);
    for (i = 4; i < 44; i++) {
        uint32_t t = ((uint32_t)rk[(i-1)*4]) | ((uint32_t)rk[(i-1)*4+1] << 8) |
                     ((uint32_t)rk[(i-1)*4+2] << 16) | ((uint32_t)rk[(i-1)*4+3] << 24);
        if ((i % 4) == 0) {
            t = ((t << 8) | (t >> 24));
            t = (uint32_t)sbox[(t >> 24) & 0xff] << 24 |
                (uint32_t)sbox[(t >> 16) & 0xff] << 16 |
                (uint32_t)sbox[(t >> 8) & 0xff] << 8 |
                sbox[t & 0xff];
            t ^= (uint32_t)rcon[i / 4] << 24;
        }
        rk[i*4]   = rk[(i-4)*4]   ^ (uint8_t)(t);
        rk[i*4+1] = rk[(i-4)*4+1] ^ (uint8_t)(t >> 8);
        rk[i*4+2] = rk[(i-4)*4+2] ^ (uint8_t)(t >> 16);
        rk[i*4+3] = rk[(i-4)*4+3] ^ (uint8_t)(t >> 24);
    }
}

static void aes128_encrypt_block(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    int r, c, i;
    memcpy(s, in, 16);
    for (r = 0; r < 10; r++) {
        for (i = 0; i < 16; i++) s[i] = sbox[s[i]];
        {
            uint8_t t;
            t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
            t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
            t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
        }
        if (r < 9) {
            for (c = 0; c < 4; c++) {
                uint8_t a=s[c*4], b=s[c*4+1], d=s[c*4+2], e=s[c*4+3];
                uint8_t x = (uint8_t)(a ^ b ^ d ^ e);
                s[c*4]   ^= xtime(a^b) ^ x;
                s[c*4+1] ^= xtime(b^d) ^ x;
                s[c*4+2] ^= xtime(d^e) ^ x;
                s[c*4+3] ^= xtime(e^a) ^ x;
            }
        }
        for (i = 0; i < 16; i++) s[i] ^= rk[r*16+i];
    }
    for (i = 0; i < 16; i++) s[i] ^= rk[160+i];
    memcpy(out, s, 16);
}

void mc_aes_cfb8_crypt(const uint8_t key[16], uint8_t iv[16],
                       uint8_t *data, int len)
{
    uint8_t rk[176];
    int i;

    aes128_key_expand(key, rk);
    for (i = 0; i < len; i++) {
        uint8_t ks[16];
        aes128_encrypt_block(rk, iv, ks);
        data[i] ^= ks[0];
        memmove(iv, iv + 1, 15);
        iv[15] = data[i];
    }
}

/* ─── RSA public encrypt (PKCS#1 v1.5, up to 2048-bit) ─── */

#define BN_LEN 256

typedef struct {
    uint8_t n[BN_LEN];
    int n_len;
} rsa_key_t;

static int mc_read_varint(const uint8_t *buf, int len, int *pos, int *out)
{
    int num = 0, read, shift = 0, p = *pos;
    do {
        if (p >= len || shift > 28) return -1;
        read = buf[p++];
        num |= (read & 0x7f) << shift;
        shift += 7;
    } while (read & 0x80);
    *pos = p;
    *out = num;
    return 0;
}

static int mc_write_varint(uint8_t *buf, int value)
{
    int pos = 0;
    do {
        uint8_t b = value & 0x7f;
        value >>= 7;
        if (value > 0) b |= 0x80;
        buf[pos++] = b;
    } while (value > 0);
    return pos;
}

static int asn1_read_len(const uint8_t *p, int len, int *pos)
{
    int l;
    if (*pos >= len) return -1;
    l = p[*pos];
    (*pos)++;
    if (l & 0x80) {
        int n = l & 0x7f, i;
        l = 0;
        for (i = 0; i < n; i++) {
            if (*pos >= len) return -1;
            l = (l << 8) | p[(*pos)++];
        }
    }
    return l;
}

static int rsa_parse_der(const uint8_t *der, int der_len, rsa_key_t *k)
{
    int pos = 0, l, found = 0;
    uint8_t mod[BN_LEN];

    memset(k, 0, sizeof(*k));
    while (pos < der_len) {
        uint8_t tag;
        const uint8_t *v;
        if (pos >= der_len) break;
        tag = der[pos++];
        l = asn1_read_len(der, der_len, &pos);
        if (l < 0 || pos + l > der_len) return -1;
        v = der + pos;
        if (tag == 0x02 && l > 32 && found == 0) {
            int copy = l;
            if (v[0] == 0x00) { v++; copy--; }
            if (copy > BN_LEN) return -1;
            memset(mod, 0, BN_LEN);
            memcpy(mod + BN_LEN - copy, v, copy);
            memcpy(k->n, mod, BN_LEN);
            k->n_len = BN_LEN;
            while (k->n_len > 1 && k->n[BN_LEN - k->n_len] == 0)
                k->n_len--;
            found = 1;
        }
        pos += l;
    }
    return found ? 0 : -1;
}

static int bn_cmp(const uint8_t *a, const uint8_t *b, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static void bn_sub_mod(uint8_t *a, const uint8_t *n, int len)
{
    int i;
    int borrow = 0;
    for (i = len - 1; i >= 0; i--) {
        int diff = (int)a[i] - (int)n[i] - borrow;
        if (diff < 0) { diff += 256; borrow = 1; } else borrow = 0;
        a[i] = (uint8_t)diff;
    }
}

static void bn_mod(uint8_t *a, const uint8_t *n, int len)
{
    while (bn_cmp(a, n, len) >= 0)
        bn_sub_mod(a, n, len);
}

static void bn_mul(const uint8_t *a, const uint8_t *b, int len, uint8_t *out)
{
    int i, j;
    memset(out, 0, len * 2);
    for (i = len - 1; i >= 0; i--) {
        uint16_t carry = 0;
        for (j = len - 1; j >= 0; j--) {
            uint32_t prod = (uint32_t)a[i] * b[j] + out[i + j + 1] + carry;
            out[i + j + 1] = (uint8_t)(prod & 0xff);
            carry = (uint16_t)(prod >> 8);
        }
        out[i] += (uint8_t)carry;
    }
}

static void bn_mod_mul(const uint8_t *a, const uint8_t *b, const uint8_t *n, int len, uint8_t *out)
{
    uint8_t tmp[BN_LEN * 2];
    bn_mul(a, b, len, tmp);
    memcpy(out, tmp + len, len);
    bn_mod(out, n, len);
}

static void modexp65537(const uint8_t *base, const uint8_t *mod, int len, uint8_t *out)
{
    uint8_t result[BN_LEN];
    uint8_t cur[BN_LEN];
    int bit;

    memset(result, 0, len);
    result[len - 1] = 1;
    memcpy(cur, base, len);
    bn_mod(cur, mod, len);

    for (bit = 0; bit <= 16; bit++) {
        if ((65537u >> bit) & 1u)
            bn_mod_mul(result, cur, mod, len, result);
        if (bit < 16)
            bn_mod_mul(cur, cur, mod, len, cur);
    }
    memcpy(out, result, len);
}

static int rsa_pkcs1_encrypt(const rsa_key_t *k, const uint8_t *msg, int msg_len, uint8_t *out)
{
    uint8_t em[BN_LEN];
    int ps_len, i;

    if (msg_len > BN_LEN - 11)
        return -1;
    ps_len = BN_LEN - msg_len - 3;
    em[0] = 0x00;
    em[1] = 0x02;
    for (i = 0; i < ps_len; i++) {
        uint8_t b;
        do { b = (uint8_t)(rand_next() & 0xff); } while (b == 0);
        em[2 + i] = b;
    }
    em[2 + ps_len] = 0x00;
    memcpy(em + 3 + ps_len, msg, msg_len);
    modexp65537(em, k->n, BN_LEN, out);
    return BN_LEN;
}

int mc_rsa_encrypt(const uint8_t *der, int der_len,
                   const uint8_t *plain, int plain_len,
                   uint8_t *out, int out_cap)
{
    rsa_key_t k;
    if (out_cap < BN_LEN || rsa_parse_der(der, der_len, &k) < 0)
        return -1;
    return rsa_pkcs1_encrypt(&k, plain, plain_len, out);
}

int mc_parse_encryption_request(const uint8_t *payload, int len,
                              uint8_t *pubkey_out, int pubkey_cap,
                              uint8_t *verify_token, int *verify_len)
{
    int pos = 0, slen, plen, tlen;
    uint8_t tmp[256];

    if (mc_read_varint(payload, len, &pos, &slen) < 0 || pos + slen > len)
        return -1;
    pos += slen;
    if (mc_read_varint(payload, len, &pos, &plen) < 0 || plen <= 0 || pos + plen > len)
        return -1;
    if (plen > pubkey_cap) return -1;
    memcpy(pubkey_out, payload + pos, plen);
    pos += plen;
    if (mc_read_varint(payload, len, &pos, &tlen) < 0 || tlen <= 0 || pos + tlen > len)
        return -1;
    if (tlen > 128) return -1;
    memcpy(verify_token, payload + pos, tlen);
    *verify_len = tlen;
    (void)tmp;
    return plen;
}

int mc_build_encryption_response(const uint8_t *shared_secret,
                                 const uint8_t *verify_token, int verify_len,
                                 const uint8_t *der_pubkey, int der_len,
                                 uint8_t *out, int out_cap)
{
    uint8_t enc_secret[BN_LEN];
    uint8_t enc_token[BN_LEN];
    int pos = 0;
    int sl, tl;

    sl = mc_rsa_encrypt(der_pubkey, der_len, shared_secret, 16, enc_secret, BN_LEN);
    tl = mc_rsa_encrypt(der_pubkey, der_len, verify_token, verify_len, enc_token, BN_LEN);
    if (sl < 0 || tl < 0 || out_cap < 16 + sl + tl)
        return -1;

    out[pos++] = 0x01;
    pos += mc_write_varint(out + pos, sl);
    memcpy(out + pos, enc_secret, sl);
    pos += sl;
    pos += mc_write_varint(out + pos, tl);
    memcpy(out + pos, enc_token, tl);
    pos += tl;
    return pos;
}
