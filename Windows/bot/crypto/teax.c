#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * TeAX stream cipher (1:1 port of pkg/teax in quantumv3).
 * key  = 16 bytes, EncKey used during key handover.
 * Init: key schedule with two-phase RC4-style swap + LCG mixing.
 * Process: keystream generation with feedback (bit-rotate + poly xor).
 */
#define TEAX_DELTA     0x61C88647u
#define TEAX_ACCUM     0xE0A4CBD6u
#define TEAX_FEEDBACK  0xD800A4u
#define TEAX_ROUNDS    5

/* server's EncKey (16 bytes) */
static const unsigned char enc_key[16] = {
    0x50, 0x4a, 0x62, 0x69, 0x4e, 0x62, 0x62, 0x65,
    0x61, 0x73, 0x64, 0x64, 0x44, 0x66, 0x73, 0x63
};

typedef struct {
    unsigned char sbox[256];
    uint32_t key[4];
} teax_ctx;

static void u32be(const uint8_t *p, uint32_t *v) {
    *v = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8)  | ((uint32_t)p[3]);
}

static void teax_init(teax_ctx *ctx, const uint8_t *key) {
    uint8_t expanded[16] = {0};
    unsigned i, j;
    int r;
    uint32_t accumulator;

    for (i = 0; i < 16; i++) {
        if (i < 16) {
            expanded[i] = key[i];
        } else {
            expanded[i] = expanded[i % 16];
        }
    }
    (void)expanded;

    for (i = 0; i < 4; i++) {
        u32be(key + i * 4, &ctx->key[i]);
    }

    for (i = 0; i < 256; i++) {
        ctx->sbox[i] = (uint8_t)((i * 167 + 13) & 0xFF);
    }

    j = 0;
    for (i = 0; i < 256; i++) {
        unsigned kIdx = i % 4;
        j = (j + ctx->sbox[i] + ((ctx->key[kIdx] >> (i % 32)) & 0xFF)) % 256;

        uint8_t tmp = ctx->sbox[i];
        ctx->sbox[i] = ctx->sbox[j];
        ctx->sbox[j] = tmp;
    }

    accumulator = TEAX_ACCUM;
    for (r = 0; r < TEAX_ROUNDS; r++) {
        for (i = 0; i < 256; i++) {
            unsigned sIdx = (i + r) % 4;
            accumulator = (accumulator * 1103515245u + 12345u) & 0xFFFFFFFFu;
            j = (j + (int)(((uint32_t)ctx->sbox[i] * accumulator) >> 24)) % 256;

            uint32_t mix = (ctx->key[sIdx] ^ accumulator) & 0xFFFFFFFFu;
            ctx->sbox[i] ^= (uint8_t)(mix & 0xFF);

            j = (j + ctx->sbox[i]) % 256;
            uint8_t tmp = ctx->sbox[i];
            ctx->sbox[i] = ctx->sbox[j];
            ctx->sbox[j] = tmp;
        }
    }
}

/* process: in-place XOR stream into out (may be same buffer) */
static void teax_process(const uint8_t *input, uint8_t *output, size_t len) {
    teax_ctx ctx;
    unsigned char sbox[256];
    unsigned i = 0, j = 0, k = 0;
    unsigned n;
    uint32_t feedback = 0x1;

    teax_init(&ctx, enc_key);
    memcpy(sbox, ctx.sbox, 256);

    for (n = 0; n < len; n++) {
        i = (i + 1) % 256;
        j = (j + sbox[i]) % 256;
        k = (k + sbox[(i + j) % 256]) % 256;

        unsigned char tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;

        unsigned char a = sbox[(i + j) % 256];
        unsigned char b = sbox[(j + k) % 256];
        unsigned char c = sbox[(a + b) % 256];

        feedback = ((feedback << 1) | (feedback >> 31)) & 0xFFFFFFFFu;
        if (feedback & 0x1) {
            feedback ^= TEAX_FEEDBACK;
        }

        unsigned char keystream = (unsigned char)(c ^ (feedback & 0xFF));
        keystream = (unsigned char)(((keystream << 3) | (keystream >> 5)) ^ (keystream >> 4));
        output[n] = input[n] ^ keystream;
    }
}

/* public */
void teax_encrypt(uint8_t *data, size_t len) {
    teax_process(data, data, len);
}
