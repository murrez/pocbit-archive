#include "proto.h"
#include "crypto/fasthash.h"
#include "crypto/chacha20.h"
#include "crypto/teax.h"

#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* big-endian helpers */
static void put_u16(uint8_t *p, uint16_t v) { p[0]=v>>8; p[1]=v&0xFF; }
static void put_u32(uint8_t *p, uint32_t v) { p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v&0xFF; }
static uint16_t get_u16(const uint8_t *p) { return (uint16_t)((p[0]<<8)|p[1]); }
static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|((uint32_t)p[3]);
}

static uint32_t rng_state = 0x1234ABCD;
static uint32_t rng(void){ rng_state=rng_state*1103515245u+12345u; return (rng_state>>16)&0x7FFF; }
static uint8_t rand_u8(void){ return (uint8_t)(rng()&0xFF); }
static size_t rand_padding(void){
    return (size_t)(QV3_MIN_PADDING + (rand_u8() % (QV3_MAX_PADDING-QV3_MIN_PADDING+1)));
}

int qv3_connect(qv3_client *c, const char *host, int port) {
    struct addrinfo hints, *res = NULL;
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;
    c->sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (c->sock == INVALID_SOCKET) { freeaddrinfo(res); return -1; }
    if (connect(c->sock, res->ai_addr, (int)res->ai_addrlen) != 0) {
        closesocket(c->sock); c->sock = INVALID_SOCKET; freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    c->state = STATE_CLIENT_HELLO;
    c->encrypted = 0;
    return 0;
}

void qv3_close(qv3_client *c) {
    if (c->sock != INVALID_SOCKET) closesocket(c->sock);
    c->sock = INVALID_SOCKET;
}

static int send_all(qv3_client *c, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = send(c->sock, (const char*)(buf+off), (int)(n-off), 0);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

static int recv_all(qv3_client *c, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = recv(c->sock, (char*)(buf+off), (int)(n-off), 0);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

int qv3_write(qv3_client *c, uint8_t op, const uint8_t *payload, size_t len) {
    uint8_t header[QV3_HEADER_SIZE];
    size_t pad = rand_padding();
    size_t outlen = QV3_HEADER_SIZE + pad + len;
    uint8_t *out = (uint8_t*)malloc(outlen ? outlen : 1);
    if (!out) return -1;
    uint8_t enc[QV3_HEADER_SIZE];

    header[0]=op; header[1]=(uint8_t)pad;
    put_u16(header+2,(uint16_t)len);
    put_u32(header+4, fasthash32(payload?payload:(const uint8_t*)"",len,QV3_FASTHASH_SEED));

    size_t o = 0;
    if (c->encrypted) {
        chacha20_encrypt(c->key,1,c->nonce,header,enc,QV3_HEADER_SIZE);
        memcpy(out+o,enc,QV3_HEADER_SIZE); o+=QV3_HEADER_SIZE;
        for (size_t i=0;i<pad;i++) out[o++]=rand_u8();
        if (len>0){ chacha20_encrypt(c->key,1,c->nonce,payload,out+o,len); o+=len; }
    } else {
        memcpy(out+o,header,QV3_HEADER_SIZE); o+=QV3_HEADER_SIZE;
        for (size_t i=0;i<pad;i++) out[o++]=rand_u8();
        if (len>0){ memcpy(out+o,payload,len); o+=len; }
    }
    int ret = send_all(c,out,outlen);
    free(out);
    return ret;
}

int qv3_read(qv3_client *c, uint8_t *op, uint8_t *buf, size_t *len, size_t cap) {
    uint8_t raw[QV3_HEADER_SIZE], header[QV3_HEADER_SIZE];
    uint16_t pktlen; uint8_t pcount; uint32_t checksum;
    if (recv_all(c,raw,QV3_HEADER_SIZE)!=0) return -1;
    if (c->encrypted) chacha20_xor(c->key,1,c->nonce,raw,header,QV3_HEADER_SIZE);
    else memcpy(header,raw,QV3_HEADER_SIZE);
    *op=header[0]; pcount=header[1]; pktlen=get_u16(header+2); checksum=get_u32(header+4);
    if (pcount>QV3_MAX_PADDING) return -1;
    if (pktlen>cap) return -1;
    uint8_t *pad=(uint8_t*)malloc(pcount?pcount:1);
    if (!pad) return -1;
    if (recv_all(c,pad,pcount)!=0){ free(pad); return -1; }
    free(pad);
    if (pktlen>0) {
        if (recv_all(c,buf,pktlen)!=0) return -1;
        if (c->encrypted) chacha20_xor(c->key,1,c->nonce,buf,buf,pktlen);
        if (fasthash32(buf,pktlen,QV3_FASTHASH_SEED)!=checksum) return -1;
        *len=pktlen;
    } else *len=0;
    return 0;
}

int qv3_handshake(qv3_client *c) {
    uint8_t body[256], op; size_t len=0; uint32_t klen;
    if (qv3_write(c,OP_CLIENT_HELLO,NULL,0)!=0) return -1;
    if (qv3_read(c,&op,body,&len,sizeof body)!=0 || op!=OP_KEY_HANDOVER) return -1;
    {
        size_t off=0; uint32_t kl,nl;
        if (len<8) return -1;
        kl=get_u32(body); (void)kl; off=4;
        if (off+32+4+4+4+12+4>len) return -1;
        memcpy(c->key,body+off,32); teax_encrypt(c->key,32); off+=32; off+=4; /* key hash */
        nl=get_u32(body+off); off+=4; (void)nl;
        memcpy(c->nonce,body+off,12); teax_encrypt(c->nonce,12); off+=12;
        (void)off;
    }
    c->encrypted=1; c->state=STATE_VERIFY_HANDOVER;
    if (qv3_write(c,OP_VERIFY_HANDOVER,NULL,0)!=0) return -1;
    if (qv3_read(c,&op,body,&len,sizeof body)!=0 || op!=OP_VERIFY_HANDOVER) return -1;
    c->state=STATE_INFORMATION;
    {
        uint8_t idb[512]; size_t n=0;
        put_u32(idb+n,0); n+=4; /* addr 0 */
        put_u32(idb+n,(uint32_t)strlen(c->name)); n+=4;
        memcpy(idb+n,c->name,strlen(c->name)); n+=strlen(c->name);
        put_u32(idb+n,c->version); n+=4;
        put_u32(idb+n,(uint32_t)strlen(c->hostname)); n+=4;
        memcpy(idb+n,c->hostname,strlen(c->hostname)); n+=strlen(c->hostname);
        put_u32(idb+n,(uint32_t)strlen(c->cwd)); n+=4;
        memcpy(idb+n,c->cwd,strlen(c->cwd)); n+=strlen(c->cwd);
        put_u32(idb+n,(uint32_t)strlen(c->kernel)); n+=4;
        memcpy(idb+n,c->kernel,strlen(c->kernel)); n+=strlen(c->kernel);
        put_u16(idb+n,c->arch); n+=2;
        idb[n++]=c->endian; idb[n++]=c->has_root;
        if (qv3_write(c,OP_IDENTIFICATION,idb,n)!=0) return -1;
    }
    if (qv3_read(c,&op,body,&len,sizeof body)!=0 || op!=OP_IDENTIFICATION) return -1;
    if (len>=4) c->conn_hash=get_u32(body);
    c->state=STATE_CONNECTED;
    return 0;
}

int qv3_report_speed(qv3_client *c, double mbps) {
    uint8_t payload[32]; size_t n=0; uint64_t bps=(uint64_t)(mbps*1000000.0);
    const char *name="speedtest"; size_t nl=strlen(name); if(nl>255)nl=255;
    put_u32(payload+n,(uint32_t)nl); n+=4;
    memcpy(payload+n,name,nl); n+=nl;
    for (int i=7;i>=0;i--) payload[n+i]=(uint8_t)(bps>>(8*(7-i)));
    n+=8;
    return qv3_write(c,OP_REPORT_SPEEDTEST,payload,n);
}
