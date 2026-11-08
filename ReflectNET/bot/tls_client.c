#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>

#include "headers/tls_client.h"
#include "headers/tls_bomb.h"
#include "headers/x25519.h"
#include "headers/sha256.h"
#include "headers/crypto_poly1305.h"
#include "headers/rand.h"
#include "headers/util.h"

#define TLS_MAX_IO 16384

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8); \
    c += d; b ^= c; b = ROTL32(b, 7)

static void chacha20_block(const uint32_t st[16], uint8_t out[64])
{
    uint32_t x[16];
    int i;

    memcpy(x, st, 64);
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = x[i] + st[i];
        out[i * 4] = (uint8_t)v;
        out[i * 4 + 1] = (uint8_t)(v >> 8);
        out[i * 4 + 2] = (uint8_t)(v >> 16);
        out[i * 4 + 3] = (uint8_t)(v >> 24);
    }
}

static void chacha20_tls_aead(const uint8_t key[32], const uint8_t iv[12],
                              uint64_t seq, const uint8_t *aad, int aad_len,
                              const uint8_t *plain, int plain_len,
                              uint8_t *out, uint8_t tag[16])
{
    uint32_t st[16];
    uint8_t block[64];
    uint8_t poly_key[32];
    int i, n;

    st[0] = 0x61707865;
    st[1] = 0x3320646e;
    st[2] = 0x79622d32;
    st[3] = 0x6b206574;
    for (i = 0; i < 8; i++)
        st[4 + i] = ((uint32_t)key[i * 4]) | (key[i * 4 + 1] << 8) |
                    (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24);
    st[12] = (uint32_t)(seq & 0xffffffffu);
    st[13] = (uint32_t)(seq >> 32);
    st[14] = ((uint32_t)iv[4] << 24) | ((uint32_t)iv[5] << 16) |
             ((uint32_t)iv[6] << 8) | iv[7];
    st[15] = ((uint32_t)iv[8] << 24) | ((uint32_t)iv[9] << 16) |
             ((uint32_t)iv[10] << 8) | iv[11];

    chacha20_block(st, block);
    memcpy(poly_key, block, 32);

    st[12] = 1;
    while (plain_len > 0) {
        chacha20_block(st, block);
        n = plain_len < 64 ? plain_len : 64;
        for (i = 0; i < n; i++)
            out[i] = plain[i] ^ block[i];
        plain += n;
        out += n;
        plain_len -= n;
        st[12]++;
    }

    {
        uint8_t mac_input[512];
        int pos = 0;
        if (aad_len + 16 > (int)sizeof(mac_input))
            aad_len = (int)sizeof(mac_input) - 16;
        memcpy(mac_input, aad, aad_len);
        pos = aad_len;
        mac_input[pos++] = (uint8_t)(plain_len >> 24);
        mac_input[pos++] = (uint8_t)(plain_len >> 16);
        mac_input[pos++] = (uint8_t)(plain_len >> 8);
        mac_input[pos++] = (uint8_t)plain_len;
        poly1305_mac(tag, poly_key, mac_input, pos);
    }
}

static void hmac_sha256(const uint8_t *key, int key_len,
                        const uint8_t *msg, int msg_len, uint8_t out[32])
{
    sha256_ctx ctx;
    uint8_t k[64];
    uint8_t ipad[64];
    uint8_t opad[64];
    int i;

    memset(k, 0, sizeof(k));
    if (key_len > 64)
        sha256_digest(key, key_len, k);
    else if (key_len > 0)
        memcpy(k, key, key_len);

    for (i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }

    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, msg, msg_len);
    sha256_final(&ctx, out);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, out, 32);
    sha256_final(&ctx, out);
}

static void hkdf_extract(const uint8_t *salt, int salt_len,
                         const uint8_t *ikm, int ikm_len, uint8_t prk[32])
{
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

static void hkdf_expand(const uint8_t prk[32], const uint8_t *info, int info_len,
                        uint8_t *out, int out_len)
{
    uint8_t t[32];
    uint8_t block[288];
    int pos = 0;
    int i;
    uint8_t counter = 1;

    memset(t, 0, 32);
    while (pos < out_len) {
        int n;
        sha256_ctx ctx;
        uint8_t tmp[32];

        sha256_init(&ctx);
        if (counter > 1)
            sha256_update(&ctx, t, 32);
        sha256_update(&ctx, info, info_len);
        sha256_update(&ctx, &counter, 1);
        sha256_final(&ctx, tmp);
        hmac_sha256(prk, 32, tmp, 32, t);

        n = out_len - pos;
        if (n > 32)
            n = 32;
        memcpy(out + pos, t, n);
        pos += n;
        counter++;
    }
    (void)block;
}

static void hkdf_expand_label(const uint8_t secret[32], const char *label,
                              const uint8_t *context, int context_len,
                              uint8_t *out, int out_len)
{
    uint8_t info[256];
    int label_len = (int)strlen(label);
    int pos = 0;

    info[pos++] = (uint8_t)out_len;
    info[pos++] = (uint8_t)(6 + label_len);
    memcpy(info + pos, "tls13 ", 6);
    pos += 6;
    memcpy(info + pos, label, label_len);
    pos += label_len;
    info[pos++] = (uint8_t)context_len;
    if (context_len > 0)
        memcpy(info + pos, context, context_len);
    pos += context_len;

    hkdf_expand(secret, info, pos, out, out_len);
}

static void derive_secret(const uint8_t secret[32], const char *label,
                          const uint8_t *transcript_hash, uint8_t out[32])
{
    hkdf_expand_label(secret, label, transcript_hash, 32, out, 32);
}

static int tls_read_all(int fd, uint8_t *buf, int want, int timeout_ms)
{
    int got = 0;
    while (got < want) {
        struct pollfd pfd = {fd, POLLIN, 0};
        int n;
        if (poll(&pfd, 1, timeout_ms) <= 0)
            return got;
        n = (int)read(fd, buf + got, want - got);
        if (n <= 0)
            break;
        got += n;
    }
    return got;
}

static int tls_find_ext(const uint8_t *ext, int ext_len, uint16_t want, uint8_t *out, int out_cap)
{
    int pos = 0;
    while (pos + 4 <= ext_len) {
        uint16_t type = (uint16_t)((ext[pos] << 8) | ext[pos + 1]);
        uint16_t len = (uint16_t)((ext[pos + 2] << 8) | ext[pos + 3]);
        pos += 4;
        if (pos + len > ext_len)
            break;
        if (type == want) {
            if (len > out_cap)
                return -1;
            memcpy(out, ext + pos, len);
            return len;
        }
        pos += len;
    }
    return -1;
}

void tls_client_reset(tls_client_t *s)
{
    if (s)
        util_zero(s, sizeof(*s));
}

int tls_client_handshake(tls_client_t *s, int fd, const char *sni, int timeout_ms)
{
    uint8_t hello[4096];
    uint8_t rx[TLS_MAX_IO];
    uint8_t shared[32];
    uint8_t early_secret[32];
    uint8_t derived[32];
    uint8_t handshake_secret[32];
    uint8_t client_hs_secret[32];
    uint8_t client_hs_key[32];
    uint8_t client_hs_iv[12];
    uint8_t transcript_hash[32];
    uint8_t finished_key[32];
    uint8_t verify_data[32];
    uint8_t client_finished[64];
    uint8_t record[4096];
    uint8_t tag[16];
    sha256_ctx tctx;
    int hello_len;
    int rx_len;
    int pos;
    int hs_len;
    int ext_len;
    uint8_t extbuf[512];
    int i;

    if (!s || fd < 0)
        return -1;

    tls_client_reset(s);
    hello_len = tls_build_client_hello(hello, sni, 0, s->pub, s->priv);
    if (hello_len <= 0)
        return -1;
    memcpy(s->client_random, hello + 11, 32);

    sha256_init(&tctx);
    sha256_update(&tctx, hello + 5, (uint32_t)(hello_len - 5));
    if (write(fd, hello, hello_len) != hello_len)
        return -1;

    rx_len = tls_read_all(fd, rx, TLS_MAX_IO, timeout_ms);
    if (rx_len < 64)
        return -1;

    pos = 0;
    while (pos + 5 <= rx_len) {
        uint16_t rlen = (uint16_t)((rx[pos + 3] << 8) | rx[pos + 4]);
        if (pos + 5 + rlen > rx_len)
            break;
        if (rx[pos] == 0x16 && rx[pos + 5] == 0x02) {
            hs_len = (rx[pos + 6] << 16) | (rx[pos + 7] << 8) | rx[pos + 8];
            if (hs_len < 32 || pos + 9 + hs_len > rx_len)
                return -1;
            memcpy(s->server_random, rx + pos + 11, 32);
            ext_len = hs_len - 32 - 3;
            if (ext_len < 4)
                return -1;
            if (tls_find_ext(rx + pos + 43, ext_len, 0x0033, extbuf, sizeof(extbuf)) < 34)
                return -1;
            if (extbuf[2] != 0x00 || extbuf[3] != 0x1d)
                return -1;
            memcpy(s->srv_pub, extbuf + 6, 32);
            sha256_update(&tctx, rx + pos + 5, (uint32_t)(5 + hs_len));
            break;
        }
        pos += 5 + rlen;
    }
    if (pos >= rx_len)
        return -1;

    x25519_scalarmult(shared, s->priv, s->srv_pub);

    sha256_final(&tctx, transcript_hash);

    util_zero(early_secret, 32);
    {
        uint8_t zeros[32];
        util_zero(zeros, 32);
        hkdf_extract(zeros, 32, zeros, 32, early_secret);
    }
    hkdf_expand_label(early_secret, "derived", transcript_hash, 32, derived, 32);
    hkdf_extract(derived, 32, shared, 32, handshake_secret);
    derive_secret(handshake_secret, "c hs traffic", transcript_hash, client_hs_secret);
    hkdf_expand_label(client_hs_secret, "key", NULL, 0, client_hs_key, 32);
    hkdf_expand_label(client_hs_secret, "iv", NULL, 0, client_hs_iv, 12);

    {
        uint8_t app_secret[32];
        derive_secret(handshake_secret, "c ap traffic", transcript_hash, app_secret);
        hkdf_expand_label(app_secret, "key", NULL, 0, s->client_app_key, 32);
        hkdf_expand_label(app_secret, "iv", NULL, 0, s->client_app_iv, 12);
    }

    hkdf_expand_label(client_hs_secret, "finished", NULL, 0, finished_key, 32);
    hmac_sha256(finished_key, 32, transcript_hash, 32, verify_data);

    record[0] = 0x16;
    record[1] = 0x03;
    record[2] = 0x03;
    client_finished[0] = 0x14;
    client_finished[1] = 0;
    client_finished[2] = 0;
    client_finished[3] = 32;
    memcpy(client_finished + 4, verify_data, 32);

    chacha20_tls_aead(client_hs_key, client_hs_iv, 0,
                      record, 5, client_finished, 36,
                      record + 5, tag);
    record[3] = 0;
    record[4] = (uint8_t)(36 + 16);
    if (write(fd, record, 5 + 36 + 16) != 5 + 36 + 16)
        return -1;

    s->app_seq = 0;
    s->ready = 1;
    (void)i;
    return 0;
}

int tls_client_send(tls_client_t *s, int fd, const uint8_t *data, int len)
{
    uint8_t record[4096];
    uint8_t tag[16];
    int chunk;
    int off = 0;

    if (!s || !s->ready || !data || len <= 0)
        return -1;

    while (off < len) {
        chunk = len - off;
        if (chunk > 3500)
            chunk = 3500;

        record[0] = 0x17;
        record[1] = 0x03;
        record[2] = 0x03;
        chacha20_tls_aead(s->client_app_key, s->client_app_iv, s->app_seq,
                          record, 5, data + off, chunk,
                          record + 5, tag);
        record[3] = (uint8_t)((chunk + 16) >> 8);
        record[4] = (uint8_t)(chunk + 16);
        if (write(fd, record, 5 + chunk + 16) != 5 + chunk + 16)
            return -1;
        s->app_seq++;
        off += chunk;
    }
    return off;
}
