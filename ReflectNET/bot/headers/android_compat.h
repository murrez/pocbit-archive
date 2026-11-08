#pragma once

#ifdef ANDROID

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <endian.h>

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif

/* Bionic may omit this when netinet/tcp.h is not pulled in. */
#ifndef TCP_NODELAY
#define TCP_NODELAY 1
#endif

#ifndef __be16
typedef uint16_t __be16;
#endif
#ifndef __be32
typedef uint32_t __be32;
#endif
#ifndef __sum16
typedef uint16_t __sum16;
#endif
#ifndef __u8
typedef uint8_t __u8;
#endif
#ifndef __u16
typedef uint16_t __u16;
#endif
#ifndef __u32
typedef uint32_t __u32;
#endif

/* Linux-layout headers missing from NDK — keep Mirai-style field names
 * (doff/syn/fin). Do NOT include <netinet/tcp.h> here (BSD layout clash). */
#ifndef __IPHDR_DEFINED
#define __IPHDR_DEFINED
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD) || defined(__LITTLE_ENDIAN) || (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint8_t  ihl:4;
    uint8_t  version:4;
#else
    uint8_t  version:4;
    uint8_t  ihl:4;
#endif
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};
#endif

#ifndef __UDPHDR_DEFINED
#define __UDPHDR_DEFINED
struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};
#endif

#ifndef __TCPHDR_DEFINED
#define __TCPHDR_DEFINED
/* Prevent Bionic netinet/tcp.h from redefining with BSD field names. */
#define _NETINET_TCP_H_
struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD) || defined(__LITTLE_ENDIAN) || (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t ece:1;
    uint16_t cwr:1;
#else
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t cwr:1;
    uint16_t ece:1;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#endif
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#endif /* ANDROID */
