#pragma once
#include <stdint.h>
#ifdef ANDROID
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
struct ethhdr {
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    uint16_t h_proto;
};
#else
#include_next <linux/if_ether.h>
#endif
