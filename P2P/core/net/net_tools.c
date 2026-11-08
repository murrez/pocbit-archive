// net_tools.c - bounded, one-shot network diagnostics for the operator shell
//
// Everything in this file is intentionally single-shot: one host, one
// connection, a hard timeout and a bounded response buffer.  There is no
// scanning, retry storm or unbounded read anywhere.

#define _GNU_SOURCE
#include "common.h"
#include "net_tools.h"

#include <ctype.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>

#ifdef P2P_HAVE_CURL
#include <curl/curl.h>
#include <pthread.h>
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* ------------------------------------------------------------------------- */
/* small helpers                                                             */
/* ------------------------------------------------------------------------- */

static uint64_t net_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int net_timeout(int timeout_ms)
{
    if (timeout_ms <= 0) return P2P_NET_DEFAULT_TIMEOUT_MS;
    if (timeout_ms > P2P_NET_MAX_TIMEOUT_MS) return P2P_NET_MAX_TIMEOUT_MS;
    return timeout_ms;
}

static void out_set(char *out, size_t out_len, const char *fmt, ...)
{
    va_list ap;
    if (!out || out_len == 0) return;
    va_start(ap, fmt);
    vsnprintf(out, out_len, fmt, ap);
    va_end(ap);
}

static void out_appendf(char *out, size_t out_len, const char *fmt, ...)
{
    size_t used;
    va_list ap;

    if (!out || out_len == 0) return;
    used = strlen(out);
    if (used + 1 >= out_len) return;

    va_start(ap, fmt);
    vsnprintf(out + used, out_len - used, fmt, ap);
    va_end(ap);
}

static void set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags >= 0) (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static void set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void disable_sigpipe(int fd)
{
#ifdef SO_NOSIGPIPE
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
    (void)fd;
#endif
}

static int wait_fd(int fd, short events, int timeout_ms)
{
    struct pollfd pfd;
    int rc;

    pfd.fd = fd;
    pfd.events = events;
    pfd.revents = 0;

    do {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);

    if (rc < 0) return -1;
    if (rc == 0) return 0;
    /* A peer that closed after sending data reports POLLIN|POLLHUP.  Treat
     * readable data as success so the caller drains it before closing. */
    if (pfd.revents & events) return 1;
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
    return 1;
}

static int resolve_host(const char *host, uint16_t port, int socktype,
                        int family, struct addrinfo **res,
                        char *err, size_t err_len)
{
    struct addrinfo hints;
    char portstr[8];
    int rc;

    if (!host || !*host) {
        out_set(err, err_len, "empty host");
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_NUMERICSERV;

    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    rc = getaddrinfo(host, portstr, &hints, res);
    if (rc != 0) {
        out_set(err, err_len, "resolve %s: %s", host, gai_strerror(rc));
        return -1;
    }
    return 0;
}

static int connect_with_timeout(int fd, const struct sockaddr *addr,
                                socklen_t addr_len, int timeout_ms)
{
    int rc;

    set_nonblock(fd);
    rc = connect(fd, addr, addr_len);
    if (rc == 0) return 0;
    if (errno != EINPROGRESS && errno != EWOULDBLOCK) return -1;

    rc = wait_fd(fd, POLLOUT, timeout_ms);
    if (rc <= 0) {
        errno = (rc == 0) ? ETIMEDOUT : errno;
        return -1;
    }

    {
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len) != 0)
            return -1;
        if (so_error != 0) {
            errno = so_error;
            return -1;
        }
    }
    return 0;
}

static int connect_host(const char *host, uint16_t port, int socktype,
                        int timeout_ms, int *out_fd,
                        char *err, size_t err_len)
{
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    int last_errno = 0;

    *out_fd = -1;
    if (resolve_host(host, port, socktype, AF_UNSPEC, &res, err, err_len) != 0)
        return -1;

    for (ai = res; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }
        set_cloexec(fd);
        disable_sigpipe(fd);

        if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen,
                                 timeout_ms) == 0) {
            *out_fd = fd;
            freeaddrinfo(res);
            return 0;
        }
        last_errno = errno;
        close(fd);
    }

    freeaddrinfo(res);
    out_set(err, err_len, "connect %s:%u: %s", host, (unsigned)port,
            last_errno ? strerror(last_errno) : "failed");
    return -1;
}

static ssize_t send_all_timeout(int fd, const void *buf, size_t len,
                                uint64_t deadline)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;

    while (off < len) {
        uint64_t now = net_now_ms();
        int remaining;
        ssize_t n;

        if (now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        remaining = (int)(deadline - now);

        n = send(fd, p + off, len - off, MSG_NOSIGNAL);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n == 0) return (ssize_t)off;
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;

        {
            int ready = wait_fd(fd, POLLOUT, remaining);
            if (ready <= 0) {
                errno = (ready == 0) ? ETIMEDOUT : errno;
                return -1;
            }
        }
    }
    return (ssize_t)off;
}

static void sanitize_copy(char *out, size_t out_len,
                          const char *data, size_t len)
{
    size_t i;
    size_t j = 0;

    if (!out || out_len == 0) return;

    for (i = 0; i < len && j + 1 < out_len; i++) {
        unsigned char c = (unsigned char)data[i];
        if (c == '\n' || c == '\t')
            out[j++] = (char)c;
        else if (c < 0x20 || c == 0x7f)
            out[j++] = '.';
        else
            out[j++] = (char)c;
    }

    if (i < len && j + 4 <= out_len) {
        memcpy(out + j, "...", 3);
        j += 3;
    }
    out[j] = '\0';
}

/* ------------------------------------------------------------------------- */
/* UDP                                                                       */
/* ------------------------------------------------------------------------- */

int p2p_net_udp_send(const char *host, uint16_t port,
                     const void *data, size_t len,
                     bool wait_reply, int timeout_ms,
                     char *out, size_t out_len)
{
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    char err[160];
    int fd = -1;
    int timeout = net_timeout(timeout_ms);
    ssize_t sent = -1;

    if (out && out_len) out[0] = '\0';
    if (!host || !data || len == 0) {
        out_set(out, out_len, "udp: empty host or payload");
        return -1;
    }

    if (resolve_host(host, port, SOCK_DGRAM, AF_UNSPEC, &res,
                     err, sizeof(err)) != 0) {
        out_set(out, out_len, "udp: %s", err);
        return -1;
    }

    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd >= 0) break;
    }
    if (!ai || fd < 0) {
        out_set(out, out_len, "udp: socket: %s", strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    set_cloexec(fd);
    set_nonblock(fd);
    disable_sigpipe(fd);

    sent = sendto(fd, data, len, 0, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(res);

    if (sent < 0) {
        out_set(out, out_len, "udp: sendto: %s", strerror(errno));
        close(fd);
        return -1;
    }

    out_set(out, out_len, "udp %s:%u sent %zd bytes\n",
            host, (unsigned)port, sent);

    if (wait_reply) {
        int ready = wait_fd(fd, POLLIN, timeout);
        if (ready > 0) {
            uint8_t buf[2048];
            struct sockaddr_storage from;
            socklen_t from_len = sizeof(from);
            ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&from, &from_len);
            if (n > 0) {
                char addr[INET6_ADDRSTRLEN] = "?";
                unsigned rport = 0;
                char preview[256];

                if (from.ss_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)&from;
                    (void)inet_ntop(AF_INET, &sin->sin_addr, addr,
                                    sizeof(addr));
                    rport = ntohs(sin->sin_port);
                } else if (from.ss_family == AF_INET6) {
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&from;
                    (void)inet_ntop(AF_INET6, &sin6->sin6_addr, addr,
                                    sizeof(addr));
                    rport = ntohs(sin6->sin6_port);
                }

                sanitize_copy(preview, sizeof(preview), (char *)buf, (size_t)n);
                out_appendf(out, out_len,
                            "reply from %s:%u (%zd bytes): %s\n",
                            addr, rport, n, preview);
            }
        } else if (ready == 0) {
            out_appendf(out, out_len, "no reply within %d ms\n", timeout);
        } else {
            out_appendf(out, out_len, "recv error: %s\n", strerror(errno));
        }
    }

    close(fd);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* TCP                                                                       */
/* ------------------------------------------------------------------------- */

int p2p_net_tcp_request(const char *host, uint16_t port,
                        const void *send_data, size_t send_len,
                        int timeout_ms, char *out, size_t out_len)
{
    char err[160];
    int fd = -1;
    int timeout = net_timeout(timeout_ms);
    uint64_t start;
    uint64_t deadline;
    uint64_t connect_ms;
    char *resp;
    size_t rx = 0;
    ssize_t tx = 0;
    char preview[512];

    if (out && out_len) out[0] = '\0';
    if (!host || !*host) {
        out_set(out, out_len, "tcp: empty host");
        return -1;
    }

    start = net_now_ms();
    if (connect_host(host, port, SOCK_STREAM, timeout, &fd,
                     err, sizeof(err)) != 0) {
        out_set(out, out_len, "tcp: %s", err);
        return -1;
    }
    connect_ms = net_now_ms() - start;
    deadline = net_now_ms() + (uint64_t)timeout;

    if (send_data && send_len > 0) {
        tx = send_all_timeout(fd, send_data, send_len, deadline);
        if (tx < 0) {
            out_set(out, out_len, "tcp: send: %s", strerror(errno));
            close(fd);
            return -1;
        }
    }

    resp = malloc(P2P_NET_MAX_RESPONSE + 1);
    if (!resp) {
        out_set(out, out_len, "tcp: out of memory");
        close(fd);
        return -1;
    }

    /* If the caller sent nothing this is a banner probe: wait a little, not
     * the full timeout.  If data was sent, wait for the full budget. */
    if (tx == 0 && timeout > 1000) timeout = 1000;
    deadline = net_now_ms() + (uint64_t)timeout;

    while (rx < P2P_NET_MAX_RESPONSE) {
        uint64_t now = net_now_ms();
        int remaining;

        if (now >= deadline) break;
        remaining = (int)(deadline - now);

        {
            int ready = wait_fd(fd, POLLIN, remaining);
            if (ready <= 0) break;
        }

        {
            ssize_t n = recv(fd, resp + rx, P2P_NET_MAX_RESPONSE - rx, 0);
            if (n > 0) {
                rx += (size_t)n;
                continue;
            }
            if (n == 0) break;
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }
    }
    resp[rx] = '\0';

    sanitize_copy(preview, sizeof(preview), resp, rx);

    out_set(out, out_len,
            "tcp %s:%u connected in %llu ms\n"
            "tx=%zd bytes rx=%zu bytes\n",
            host, (unsigned)port,
            (unsigned long long)connect_ms, tx, rx);
    if (rx > 0)
        out_appendf(out, out_len, "--- reply ---\n%s\n", preview);
    else
        out_appendf(out, out_len, "no data received\n");

    free(resp);
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* ICMP echo                                                                 */
/* ------------------------------------------------------------------------- */

typedef struct __attribute__((packed)) {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} net_icmp_echo_t;

static uint16_t net_icmp_checksum(const void *data, size_t len)
{
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1)
        sum += *(const uint8_t *)p;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}

int p2p_net_icmp_ping(const char *host, int count, int timeout_ms,
                      char *out, size_t out_len)
{
    struct addrinfo *res = NULL;
    char err[160];
    int fd = -1;
    int timeout = net_timeout(timeout_ms);
    bool raw = false;
    int sent = 0;
    int received = 0;
    uint16_t ident = (uint16_t)(getpid() & 0xffff);

    if (out && out_len) out[0] = '\0';
    if (!host || !*host) {
        out_set(out, out_len, "icmp: empty host");
        return -1;
    }
    if (count < 1) count = 1;
    if (count > P2P_NET_MAX_ICMP_COUNT) count = P2P_NET_MAX_ICMP_COUNT;

    if (resolve_host(host, 0, SOCK_RAW, AF_INET, &res,
                     err, sizeof(err)) != 0) {
        out_set(out, out_len, "icmp: %s", err);
        return -1;
    }

    /* Unprivileged ping sockets are tried first; raw sockets need root. */
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (fd < 0) {
        fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        raw = true;
    }
    if (fd < 0) {
        out_set(out, out_len,
                "icmp: cannot create socket: %s "
                "(root or ping_group_range required)",
                strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    set_cloexec(fd);
    set_nonblock(fd);
    disable_sigpipe(fd);

    out_set(out, out_len, "icmp %s (%d packet%s)\n",
            host, count, count == 1 ? "" : "s");

    for (int i = 0; i < count; i++) {
        uint8_t packet[8 + 32];
        net_icmp_echo_t *hdr = (net_icmp_echo_t *)packet;
        struct sockaddr *addr = res->ai_addr;
        socklen_t addr_len = res->ai_addrlen;
        uint16_t seq = (uint16_t)(i + 1);
        uint64_t start;
        int ready;

        memset(packet, 0, sizeof(packet));
        hdr->type = 8;
        hdr->code = 0;
        hdr->id = htons(ident);
        hdr->seq = htons(seq);
        for (size_t k = sizeof(net_icmp_echo_t); k < sizeof(packet); k++)
            packet[k] = (uint8_t)(k & 0xff);
        hdr->checksum = net_icmp_checksum(packet, sizeof(packet));

        start = net_now_ms();
        if (sendto(fd, packet, sizeof(packet), 0, addr, addr_len) < 0) {
            out_appendf(out, out_len, "seq=%u send error: %s\n",
                        (unsigned)seq, strerror(errno));
            continue;
        }
        sent++;

        ready = wait_fd(fd, POLLIN, timeout);
        if (ready <= 0) {
            out_appendf(out, out_len, "seq=%u timeout\n", (unsigned)seq);
            continue;
        }

        {
            uint8_t buf[1024];
            struct sockaddr_storage from;
            socklen_t from_len = sizeof(from);
            ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&from, &from_len);
            size_t off = 0;
            int ttl = -1;
            net_icmp_echo_t *reply;

            if (n <= 0) {
                out_appendf(out, out_len, "seq=%u recv error: %s\n",
                            (unsigned)seq, strerror(errno));
                continue;
            }

            /* Some platforms (notably macOS) return the IPv4 header even on
             * SOCK_DGRAM ICMP sockets.  Detect it by the version nibble. */
            if (n >= 20 && (buf[0] >> 4) == 4) {
                ttl = buf[8];
                off = (size_t)(buf[0] & 0x0f) * 4u;
            }

            if ((size_t)n < off + sizeof(net_icmp_echo_t)) {
                out_appendf(out, out_len, "seq=%u short reply\n",
                            (unsigned)seq);
                continue;
            }

            reply = (net_icmp_echo_t *)(buf + off);
            if (reply->type != 0 || reply->code != 0 ||
                reply->seq != htons(seq)) {
                out_appendf(out, out_len,
                            "seq=%u unexpected reply type=%u code=%u "
                            "id=%u rseq=%u\n",
                            (unsigned)seq, (unsigned)reply->type,
                            (unsigned)reply->code,
                            (unsigned)ntohs(reply->id),
                            (unsigned)ntohs(reply->seq));
                continue;
            }
            if (raw && reply->id != htons(ident)) {
                out_appendf(out, out_len, "seq=%u id mismatch\n",
                            (unsigned)seq);
                continue;
            }

            received++;
            {
                double rtt = (double)(net_now_ms() - start);
                if (ttl >= 0)
                    out_appendf(out, out_len,
                                "seq=%u ttl=%d time=%.1f ms\n",
                                (unsigned)seq, ttl, rtt);
                else
                    out_appendf(out, out_len,
                                "seq=%u time=%.1f ms\n",
                                (unsigned)seq, rtt);
            }
        }
    }

    out_appendf(out, out_len,
                "--- %d sent, %d received, %d%% loss ---\n",
                sent, received,
                sent > 0 ? (int)(((sent - received) * 100) / sent) : 0);

    freeaddrinfo(res);
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* URL parsing (shared by the built-in HTTP client and Discord validation)    */
/* ------------------------------------------------------------------------- */

typedef struct {
    char scheme[8];
    char host[256];
    char host_header[300];
    uint16_t port;
    char path[1024];
} net_url_t;

static bool url_host_is_discord(const char *host)
{
    static const char *domains[] = {"discord.com", "discordapp.com"};
    size_t hlen = strlen(host);

    for (size_t i = 0; i < sizeof(domains) / sizeof(domains[0]); i++) {
        size_t dlen = strlen(domains[i]);
        if (hlen == dlen && strcasecmp(host, domains[i]) == 0)
            return true;
        if (hlen > dlen && host[hlen - dlen - 1] == '.' &&
            strcasecmp(host + hlen - dlen, domains[i]) == 0)
            return true;
    }
    return false;
}

static bool parse_url(const char *url, net_url_t *u)
{
    const char *p;
    const char *scheme_end;
    const char *host_start;
    const char *host_end;
    const char *path_start;
    size_t scheme_len;
    size_t host_len;

    if (!url || !u) return false;
    memset(u, 0, sizeof(*u));
    p = url;

    while (*p == ' ' || *p == '\t') p++;

    scheme_end = strstr(p, "://");
    if (scheme_end) {
        scheme_len = (size_t)(scheme_end - p);
        if (scheme_len == 0 || scheme_len >= sizeof(u->scheme)) return false;
        for (size_t i = 0; i < scheme_len; i++)
            u->scheme[i] = (char)tolower((unsigned char)p[i]);
        u->scheme[scheme_len] = '\0';
        p = scheme_end + 3;
    } else {
        snprintf(u->scheme, sizeof(u->scheme), "http");
    }

    if (strcmp(u->scheme, "http") != 0 && strcmp(u->scheme, "https") != 0)
        return false;

    host_start = p;
    if (*host_start == '[') {
        host_start++;
        host_end = strchr(host_start, ']');
        if (!host_end) return false;
        p = host_end + 1;
    } else {
        host_end = host_start;
        while (*host_end && *host_end != ':' && *host_end != '/' &&
               *host_end != '?' && *host_end != '#')
            host_end++;
        p = host_end;
    }

    host_len = (size_t)(host_end - host_start);
    if (host_len == 0 || host_len >= sizeof(u->host)) return false;
    memcpy(u->host, host_start, host_len);
    u->host[host_len] = '\0';

    for (size_t i = 0; i < host_len; i++) {
        unsigned char c = (unsigned char)u->host[i];
        if (c <= 0x20 || c == 0x7f) return false;
    }

    u->port = (strcmp(u->scheme, "https") == 0) ? 443 : 80;
    if (*p == ':') {
        char *end = NULL;
        long port = strtol(p + 1, &end, 10);
        if (end == p + 1 || port < 1 || port > 65535) return false;
        u->port = (uint16_t)port;
        p = end;
    }

    if (*p == '/') {
        path_start = p;
    } else if (*p == '?' || *p == '#') {
        snprintf(u->path, sizeof(u->path), "/%s", p);
        char *hash = strchr(u->path, '#');
        if (hash) *hash = '\0';
        path_start = NULL;
    } else if (*p == '\0') {
        snprintf(u->path, sizeof(u->path), "/");
        path_start = NULL;
    } else {
        return false;
    }

    if (path_start) {
        size_t plen = strcspn(path_start, "#");
        if (plen >= sizeof(u->path)) plen = sizeof(u->path) - 1;
        memcpy(u->path, path_start, plen);
        u->path[plen] = '\0';
    }

    if (strchr(u->host, ':'))
        snprintf(u->host_header, sizeof(u->host_header), "[%s]", u->host);
    else
        snprintf(u->host_header, sizeof(u->host_header), "%s", u->host);

    if (u->port != 80 && u->port != 443) {
        char tmp[sizeof(u->host_header)];
        snprintf(tmp, sizeof(tmp), "%s:%u", u->host_header,
                 (unsigned)u->port);
        snprintf(u->host_header, sizeof(u->host_header), "%s", tmp);
    }

    return true;
}

/* ------------------------------------------------------------------------- */
/* HTTP: built-in client (plain HTTP only)                                   */
/* ------------------------------------------------------------------------- */

#ifndef P2P_HAVE_CURL

static const char *ci_find(const char *hay, size_t hay_len,
                           const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0 || hay_len < nlen) return NULL;
    for (size_t i = 0; i + nlen <= hay_len; i++) {
        if (strncasecmp(hay + i, needle, nlen) == 0)
            return hay + i;
    }
    return NULL;
}

static bool header_get(const char *headers, size_t headers_len,
                       const char *name, char *val, size_t val_len)
{
    const char *line = headers;
    const char *end = headers + headers_len;
    size_t name_len = strlen(name);

    while (line < end) {
        const char *eol = line;
        while (eol < end && *eol != '\r' && *eol != '\n') eol++;

        if ((size_t)(eol - line) > name_len &&
            strncasecmp(line, name, name_len) == 0 &&
            line[name_len] == ':') {
            const char *v = line + name_len + 1;
            size_t vlen;
            while (v < eol && (*v == ' ' || *v == '\t')) v++;
            vlen = (size_t)(eol - v);
            while (vlen > 0 && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t'))
                vlen--;
            if (vlen >= val_len) vlen = val_len - 1;
            memcpy(val, v, vlen);
            val[vlen] = '\0';
            return true;
        }

        line = eol;
        while (line < end && (*line == '\r' || *line == '\n')) line++;
    }
    return false;
}

static size_t decode_chunked(const char *in, size_t len,
                             char *out, size_t out_cap)
{
    size_t ip = 0;
    size_t op = 0;

    while (ip < len) {
        size_t chunk = 0;
        bool any = false;

        while (ip < len && in[ip] != '\r' && in[ip] != '\n' &&
               in[ip] != ';') {
            char c = in[ip];
            int v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else break;
            chunk = chunk * 16u + (size_t)v;
            any = true;
            ip++;
        }

        while (ip < len && in[ip] != '\n') ip++;
        if (ip < len) ip++;

        if (!any || chunk == 0) break;
        if (ip + chunk > len) chunk = len - ip;
        if (op + chunk > out_cap) chunk = out_cap - op;
        if (chunk == 0) break;
        memcpy(out + op, in + ip, chunk);
        op += chunk;
        ip += chunk;

        while (ip < len && (in[ip] == '\r' || in[ip] == '\n')) ip++;
    }
    return op;
}

static void resolve_redirect(const net_url_t *base, const char *loc,
                             char *out, size_t out_len)
{
    if (!loc || !*loc) {
        snprintf(out, out_len, "%s", base->host_header);
        return;
    }

    if (strncasecmp(loc, "http://", 7) == 0 ||
        strncasecmp(loc, "https://", 8) == 0) {
        snprintf(out, out_len, "%s", loc);
        return;
    }
    if (strncmp(loc, "//", 2) == 0) {
        snprintf(out, out_len, "%s:%s", base->scheme, loc);
        return;
    }
    if (loc[0] == '/') {
        snprintf(out, out_len, "%s://%s%s", base->scheme,
                 base->host_header, loc);
        return;
    }

    {
        char dir[sizeof(base->path)];
        const char *slash = strrchr(base->path, '/');
        size_t dlen;

        if (!slash) {
            snprintf(dir, sizeof(dir), "/");
        } else {
            dlen = (size_t)(slash - base->path) + 1;
            if (dlen >= sizeof(dir)) dlen = sizeof(dir) - 1;
            memcpy(dir, base->path, dlen);
            dir[dlen] = '\0';
        }
        snprintf(out, out_len, "%s://%s%s%s", base->scheme,
                 base->host_header, dir, loc);
    }
}

static int http_builtin(const char *method, const char *url,
                        const char *content_type, const char *body,
                        int timeout_ms, char *out, size_t out_len)
{
    char cur_url[1024];
    char cur_method[8];
    const char *cur_body = body;
    const char *cur_ct = content_type;
    int timeout = net_timeout(timeout_ms);

    if (!method || !*method) method = "GET";
    snprintf(cur_method, sizeof(cur_method), "%s", method);
    snprintf(cur_url, sizeof(cur_url), "%s", url);

    for (int redirect = 0; redirect < 4; redirect++) {
        net_url_t u;
        char err[160];
        int fd = -1;
        char *req = NULL;
        char *resp = NULL;
        size_t body_len = cur_body ? strlen(cur_body) : 0;
        size_t req_cap;
        int req_len;
        uint64_t deadline;
        size_t rx = 0;
        const char *hdr_end;
        int status = -1;
        char location[1024];
        char te[64];
        bool chunked = false;

        if (!parse_url(cur_url, &u)) {
            out_set(out, out_len, "http: invalid URL");
            return -1;
        }
        if (strcmp(u.scheme, "https") == 0) {
            out_set(out, out_len,
                    "http: https requires a libcurl-enabled build");
            return -1;
        }

        if (connect_host(u.host, u.port, SOCK_STREAM, timeout, &fd,
                         err, sizeof(err)) != 0) {
            out_set(out, out_len, "http: %s", err);
            return -1;
        }

        req_cap = 1024 + strlen(u.path) + body_len;
        req = malloc(req_cap);
        if (!req) {
            out_set(out, out_len, "http: out of memory");
            close(fd);
            return -1;
        }

        req_len = snprintf(req, req_cap,
                           "%s %s HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "User-Agent: p2p_agent/1.0\r\n"
                           "Accept: */*\r\n"
                           "Accept-Encoding: identity\r\n"
                           "Connection: close\r\n",
                           cur_method, u.path, u.host_header);
        if (req_len < 0 || (size_t)req_len >= req_cap) {
            out_set(out, out_len, "http: request too large");
            free(req);
            close(fd);
            return -1;
        }

        if (cur_body && body_len > 0) {
            int n;
            if (cur_ct && *cur_ct)
                n = snprintf(req + req_len, req_cap - (size_t)req_len,
                             "Content-Type: %s\r\n", cur_ct);
            else
                n = snprintf(req + req_len, req_cap - (size_t)req_len,
                             "Content-Type: text/plain; charset=utf-8\r\n");
            if (n > 0) req_len += n;
            n = snprintf(req + req_len, req_cap - (size_t)req_len,
                         "Content-Length: %zu\r\n", body_len);
            if (n > 0) req_len += n;
        } else if (strcasecmp(cur_method, "POST") == 0 ||
                   strcasecmp(cur_method, "PUT") == 0 ||
                   strcasecmp(cur_method, "PATCH") == 0) {
            int n = snprintf(req + req_len, req_cap - (size_t)req_len,
                             "Content-Length: 0\r\n");
            if (n > 0) req_len += n;
        }
        req_len += snprintf(req + req_len, req_cap - (size_t)req_len,
                            "\r\n");

        if ((size_t)req_len + body_len >= req_cap) {
            out_set(out, out_len, "http: request too large");
            free(req);
            close(fd);
            return -1;
        }
        if (body_len > 0) {
            memcpy(req + req_len, cur_body, body_len);
            req_len += (int)body_len;
        }

        deadline = net_now_ms() + (uint64_t)timeout;
        if (send_all_timeout(fd, req, (size_t)req_len, deadline) < 0) {
            out_set(out, out_len, "http: send: %s", strerror(errno));
            free(req);
            close(fd);
            return -1;
        }
        free(req);

        deadline = net_now_ms() + (uint64_t)timeout;

        resp = malloc(P2P_NET_MAX_RESPONSE + 1);
        if (!resp) {
            out_set(out, out_len, "http: out of memory");
            close(fd);
            return -1;
        }

        while (rx < P2P_NET_MAX_RESPONSE) {
            uint64_t now = net_now_ms();
            int remaining;
            int ready;
            ssize_t n;

            if (now >= deadline) break;
            remaining = (int)(deadline - now);
            ready = wait_fd(fd, POLLIN, remaining);
            if (ready <= 0) break;

            n = recv(fd, resp + rx, P2P_NET_MAX_RESPONSE - rx, 0);
            if (n > 0) {
                rx += (size_t)n;
                continue;
            }
            if (n == 0) break;
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            break;
        }
        close(fd);
        resp[rx] = '\0';

        hdr_end = strstr(resp, "\r\n\r\n");
        if (!hdr_end) {
            out_set(out, out_len, "http: malformed response");
            free(resp);
            return -1;
        }

        {
            const char *sp = strchr(resp, ' ');
            if (sp) status = (int)strtol(sp + 1, NULL, 10);
        }
        if (status < 100 || status > 599) {
            out_set(out, out_len, "http: invalid status line");
            free(resp);
            return -1;
        }

        {
            size_t headers_len = (size_t)(hdr_end - resp);
            if (header_get(resp, headers_len, "Transfer-Encoding",
                           te, sizeof(te)) &&
                ci_find(te, strlen(te), "chunked")) {
                chunked = true;
            }
            (void)header_get(resp, headers_len, "Location",
                             location, sizeof(location));
        }

        {
            const char *body_start = hdr_end + 4;
            size_t body_size = rx - (size_t)(body_start - resp);

            if (chunked) {
                char *decoded = malloc(P2P_NET_MAX_RESPONSE + 1);
                if (decoded) {
                    size_t dlen = decode_chunked(body_start, body_size,
                                                 decoded,
                                                 P2P_NET_MAX_RESPONSE);
                    decoded[dlen] = '\0';
                    sanitize_copy(out, out_len, decoded, dlen);
                    free(decoded);
                } else {
                    sanitize_copy(out, out_len, body_start, body_size);
                }
            } else {
                sanitize_copy(out, out_len, body_start, body_size);
            }
        }

        if ((status == 301 || status == 302 || status == 303 ||
             status == 307 || status == 308) && location[0]) {
            char next_url[1024];
            resolve_redirect(&u, location, next_url, sizeof(next_url));
            snprintf(cur_url, sizeof(cur_url), "%s", next_url);

            if (status == 303 ||
                ((status == 301 || status == 302) &&
                 strcasecmp(cur_method, "POST") == 0)) {
                snprintf(cur_method, sizeof(cur_method), "GET");
                cur_body = NULL;
                cur_ct = NULL;
            }
            free(resp);
            continue;
        }

        free(resp);
        return status;
    }

    out_set(out, out_len, "http: too many redirects");
    return -1;
}

#endif /* !P2P_HAVE_CURL */

/* ------------------------------------------------------------------------- */
/* HTTP: optional libcurl backend (also provides HTTPS)                      */
/* ------------------------------------------------------------------------- */

#ifdef P2P_HAVE_CURL

static pthread_once_t curl_once = PTHREAD_ONCE_INIT;

static void curl_global_init_once(void)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

typedef struct {
    char *data;
    size_t len;
    size_t cap;
    bool truncated;
} curl_buffer_t;

static size_t curl_write_cb(char *ptr, size_t size, size_t nmemb,
                            void *userdata)
{
    size_t total = size * nmemb;
    curl_buffer_t *b = (curl_buffer_t *)userdata;

    if (b->len + total > b->cap) {
        total = b->cap - b->len;
        b->truncated = true;
    }
    if (total > 0) {
        memcpy(b->data + b->len, ptr, total);
        b->len += total;
    }
    /* Claim the whole chunk so libcurl keeps downloading (and discarding
     * anything past our cap) instead of aborting with a write error. */
    return size * nmemb;
}

static int http_curl(const char *method, const char *url,
                     const char *content_type, const char *body,
                     int timeout_ms, char *out, size_t out_len)
{
    CURL *h;
    CURLcode rc;
    struct curl_slist *headers = NULL;
    curl_buffer_t buf;
    long status = 0;
    int timeout = net_timeout(timeout_ms);

    if (out && out_len) out[0] = '\0';
    if (pthread_once(&curl_once, curl_global_init_once) != 0) {
        out_set(out, out_len, "http: curl init failed");
        return -1;
    }

    h = curl_easy_init();
    if (!h) {
        out_set(out, out_len, "http: curl_easy_init failed");
        return -1;
    }

    buf.cap = P2P_NET_MAX_RESPONSE * 16;
    buf.len = 0;
    buf.truncated = false;
    buf.data = malloc(buf.cap + 1);
    if (!buf.data) {
        out_set(out, out_len, "http: out of memory");
        curl_easy_cleanup(h);
        return -1;
    }
    buf.data[0] = '\0';

    if (!method || !*method) method = "GET";

    if (content_type && *content_type) {
        char ct[256];
        snprintf(ct, sizeof(ct), "Content-Type: %s", content_type);
        headers = curl_slist_append(headers, ct);
    }
    headers = curl_slist_append(headers, "Expect:");

    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_USERAGENT, "p2p_agent/1.0");
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, (long)timeout);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS,
                     (long)(timeout < 5000 ? timeout : 5000));
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(h, CURLOPT_ACCEPT_ENCODING, "identity");

    if (strcasecmp(method, "POST") == 0) {
        curl_easy_setopt(h, CURLOPT_POST, 1L);
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, body ? body : "");
        curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE,
                         (long)(body ? strlen(body) : 0));
    } else if (strcasecmp(method, "HEAD") == 0) {
        curl_easy_setopt(h, CURLOPT_NOBODY, 1L);
    } else if (strcasecmp(method, "GET") != 0) {
        curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, method);
        if (body) {
            curl_easy_setopt(h, CURLOPT_POSTFIELDS, body);
            curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
        }
    }

    rc = curl_easy_perform(h);
    if (rc != CURLE_OK) {
        out_set(out, out_len, "http: %s", curl_easy_strerror(rc));
        curl_slist_free_all(headers);
        curl_easy_cleanup(h);
        free(buf.data);
        return -1;
    }

    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status);
    sanitize_copy(out, out_len, buf.data, buf.len);
    if (buf.truncated)
        out_appendf(out, out_len, "\n[response truncated]");

    curl_slist_free_all(headers);
    curl_easy_cleanup(h);
    free(buf.data);

    if (status < 100 || status > 599) {
        out_set(out, out_len, "http: invalid response code");
        return -1;
    }
    return (int)status;
}

#endif /* P2P_HAVE_CURL */

int p2p_net_http_request(const char *method, const char *url,
                         const char *content_type, const char *body,
                         int timeout_ms, char *out, size_t out_len)
{
    if (out && out_len) out[0] = '\0';
    if (!url || !*url) {
        out_set(out, out_len, "http: empty URL");
        return -1;
    }

#ifdef P2P_HAVE_CURL
    return http_curl(method, url, content_type, body, timeout_ms,
                     out, out_len);
#else
    return http_builtin(method, url, content_type, body, timeout_ms,
                        out, out_len);
#endif
}

/* ------------------------------------------------------------------------- */
/* Minecraft Java server-list ping                                           */
/* ------------------------------------------------------------------------- */

static bool mc_write_varint(uint8_t *buf, size_t cap, size_t *off,
                            int32_t value)
{
    uint32_t v = (uint32_t)value;
    do {
        uint8_t b;
        if (*off >= cap) return false;
        b = (uint8_t)(v & 0x7f);
        v >>= 7;
        if (v) b |= 0x80;
        buf[(*off)++] = b;
    } while (v);
    return true;
}

static bool mc_read_varint_buf(const uint8_t *buf, size_t len, size_t *off,
                               int32_t *value)
{
    uint32_t result = 0;
    int shift = 0;

    while (shift < 35) {
        uint8_t b;
        if (*off >= len) return false;
        b = buf[(*off)++];
        result |= (uint32_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) {
            *value = (int32_t)result;
            return true;
        }
        shift += 7;
    }
    return false;
}

static bool mc_read_varint_fd(int fd, uint64_t deadline, int32_t *value)
{
    uint32_t result = 0;
    int shift = 0;

    while (shift < 35) {
        uint8_t b;
        for (;;) {
            uint64_t now = net_now_ms();
            int remaining;
            int ready;

            if (now >= deadline) return false;
            remaining = (int)(deadline - now);
            ready = wait_fd(fd, POLLIN, remaining);
            if (ready <= 0) return false;

            {
                ssize_t n = recv(fd, &b, 1, 0);
                if (n == 1) break;
                if (n < 0 && (errno == EINTR || errno == EAGAIN ||
                              errno == EWOULDBLOCK))
                    continue;
                return false;
            }
        }

        result |= (uint32_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) {
            *value = (int32_t)result;
            return true;
        }
        shift += 7;
    }
    return false;
}

static bool mc_read_exact(int fd, uint8_t *buf, size_t len, uint64_t deadline)
{
    size_t off = 0;

    while (off < len) {
        uint64_t now = net_now_ms();
        int remaining;
        int ready;
        ssize_t n;

        if (now >= deadline) return false;
        remaining = (int)(deadline - now);
        ready = wait_fd(fd, POLLIN, remaining);
        if (ready <= 0) return false;

        n = recv(fd, buf + off, len - off, 0);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n == 0) return false;
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            continue;
        return false;
    }
    return true;
}

static void json_unescape(const char *in, size_t len,
                          char *out, size_t out_len)
{
    size_t ip = 0;
    size_t op = 0;

    if (!out || out_len == 0) return;

    while (ip < len && op + 1 < out_len) {
        char c = in[ip++];
        if (c != '\\') {
            out[op++] = c;
            continue;
        }
        if (ip >= len) break;
        c = in[ip++];
        switch (c) {
        case '"':  out[op++] = '"';  break;
        case '\\': out[op++] = '\\'; break;
        case '/':  out[op++] = '/';  break;
        case 'b':  out[op++] = '\b'; break;
        case 'f':  out[op++] = '\f'; break;
        case 'n':  out[op++] = '\n'; break;
        case 'r':  out[op++] = '\r'; break;
        case 't':  out[op++] = '\t'; break;
        case 'u': {
            unsigned value = 0;
            bool ok = true;
            for (int k = 0; k < 4; k++) {
                int v;
                if (ip >= len) { ok = false; break; }
                c = in[ip++];
                if (c >= '0' && c <= '9') v = c - '0';
                else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
                else { ok = false; break; }
                value = (value << 4) | (unsigned)v;
            }
            if (!ok) break;
            if (value < 0x80) {
                out[op++] = (char)value;
            } else if (value < 0x800) {
                if (op + 2 >= out_len) break;
                out[op++] = (char)(0xc0 | (value >> 6));
                out[op++] = (char)(0x80 | (value & 0x3f));
            } else {
                if (op + 3 >= out_len) break;
                out[op++] = (char)(0xe0 | (value >> 12));
                out[op++] = (char)(0x80 | ((value >> 6) & 0x3f));
                out[op++] = (char)(0x80 | (value & 0x3f));
            }
            break;
        }
        default:
            out[op++] = c;
            break;
        }
    }
    out[op] = '\0';
}

static const char *json_skip_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
        p++;
    return p;
}

static const char *json_skip_value(const char *p, const char *end)
{
    if (p >= end) return NULL;

    if (*p == '"') {
        p++;
        while (p < end) {
            if (*p == '\\') {
                p += 2;
                continue;
            }
            if (*p == '"') return p + 1;
            p++;
        }
        return NULL;
    }

    if (*p == '{' || *p == '[') {
        char open = *p;
        char close = (open == '{') ? '}' : ']';
        int depth = 0;
        bool in_str = false;
        bool esc = false;

        while (p < end) {
            char c = *p++;
            if (in_str) {
                if (esc) {
                    esc = false;
                } else if (c == '\\') {
                    esc = true;
                } else if (c == '"') {
                    in_str = false;
                }
                continue;
            }
            if (c == '"') {
                in_str = true;
            } else if (c == open) {
                depth++;
            } else if (c == close) {
                depth--;
                if (depth == 0) return p;
            }
        }
        return NULL;
    }

    while (p < end && *p != ',' && *p != '}' && *p != ']' &&
           *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
        p++;
    return p;
}

static const char *json_find_key(const char *p, const char *end,
                                 const char *key)
{
    size_t klen = strlen(key);
    bool in_str = false;
    bool esc = false;

    while (p < end) {
        char c = *p;

        if (in_str) {
            if (esc) {
                esc = false;
                p++;
                continue;
            }
            if (c == '\\') {
                esc = true;
                p++;
                continue;
            }
            if (c == '"') in_str = false;
            p++;
            continue;
        }

        if (c == '"') {
            const char *ks = p + 1;
            const char *ke = ks;
            while (ke < end) {
                if (*ke == '\\') {
                    ke += 2;
                    continue;
                }
                if (*ke == '"') break;
                ke++;
            }
            if (ke < end && (size_t)(ke - ks) == klen &&
                memcmp(ks, key, klen) == 0) {
                const char *q = json_skip_ws(ke + 1, end);
                if (q < end && *q == ':')
                    return p;
            }
            p = (ke < end) ? ke + 1 : end;
            continue;
        }

        p++;
    }
    return NULL;
}

static const char *json_value_after(const char *json, const char *end,
                                    const char *key, const char **val_end)
{
    const char *k = json_find_key(json, end, key);
    const char *p;

    if (!k) return NULL;
    p = k + 1;
    while (p < end && *p != '"') {
        if (*p == '\\') p++;
        p++;
    }
    if (p >= end) return NULL;
    p = json_skip_ws(p + 1, end);
    if (p >= end || *p != ':') return NULL;
    p = json_skip_ws(p + 1, end);
    if (p >= end) return NULL;

    {
        const char *e = json_skip_value(p, end);
        if (!e) return NULL;
        if (val_end) *val_end = e;
    }
    return p;
}

static bool json_string_after(const char *json, const char *end,
                              const char *key, char *out, size_t out_len)
{
    const char *ve = NULL;
    const char *v = json_value_after(json, end, key, &ve);

    if (!v || *v != '"' || ve <= v + 1) return false;
    json_unescape(v + 1, (size_t)(ve - v - 2), out, out_len);
    return true;
}

static bool json_long_after(const char *json, const char *end,
                            const char *key, long *out)
{
    const char *ve = NULL;
    const char *v = json_value_after(json, end, key, &ve);
    char tmp[32];
    size_t len;

    if (!v || !out) return false;
    len = (size_t)(ve - v);
    if (len == 0 || len >= sizeof(tmp)) return false;
    memcpy(tmp, v, len);
    tmp[len] = '\0';
    *out = strtol(tmp, NULL, 10);
    return true;
}

static void json_collect_text(const char *obj, const char *end,
                              char *out, size_t out_len)
{
    const char *p = obj;

    if (!out || out_len == 0) return;
    out[0] = '\0';

    while (p < end) {
        const char *ve = NULL;
        const char *v = json_value_after(p, end, "text", &ve);
        if (!v || ve <= p) break;
        if (*v == '"') {
            char tmp[512];
            json_unescape(v + 1, (size_t)(ve - v - 2), tmp, sizeof(tmp));
            if (tmp[0]) {
                size_t used = strlen(out);
                if (used + 1 < out_len)
                    snprintf(out + used, out_len - used, "%s", tmp);
            }
        }
        p = ve;
    }
}

int p2p_net_minecraft_status(const char *host, uint16_t port,
                             int timeout_ms, char *out, size_t out_len)
{
    char err[160];
    int fd = -1;
    int timeout = net_timeout(timeout_ms);
    uint64_t deadline;
    uint8_t payload[1200];
    uint8_t frame[1300];
    size_t po;
    size_t fo;
    int32_t frame_len;
    uint8_t *frame_data;
    int32_t packet_id;
    int32_t json_len;
    char *json;
    char version[128] = "?";
    char motd[512] = "";
    long online = -1;
    long max_players = -1;
    double latency_ms = -1.0;
    size_t hlen;

    if (out && out_len) out[0] = '\0';
    if (!host || !*host) {
        out_set(out, out_len, "minecraft: empty host");
        return -1;
    }
    hlen = strlen(host);
    if (hlen == 0 || hlen > 255) {
        out_set(out, out_len, "minecraft: host must be 1..255 bytes");
        return -1;
    }

    if (connect_host(host, port, SOCK_STREAM, timeout, &fd,
                     err, sizeof(err)) != 0) {
        out_set(out, out_len, "minecraft: %s", err);
        return -1;
    }
    deadline = net_now_ms() + (uint64_t)timeout;

    /* Handshake: packet id 0, protocol 47, address, port, next state 1. */
    po = 0;
    if (!mc_write_varint(payload, sizeof(payload), &po, 0x00) ||
        !mc_write_varint(payload, sizeof(payload), &po, 47) ||
        !mc_write_varint(payload, sizeof(payload), &po, (int32_t)hlen) ||
        po + hlen + 3 > sizeof(payload)) {
        out_set(out, out_len, "minecraft: handshake too large");
        close(fd);
        return -1;
    }
    memcpy(payload + po, host, hlen);
    po += hlen;
    payload[po++] = (uint8_t)(port >> 8);
    payload[po++] = (uint8_t)(port & 0xff);
    if (!mc_write_varint(payload, sizeof(payload), &po, 1)) {
        out_set(out, out_len, "minecraft: handshake too large");
        close(fd);
        return -1;
    }

    fo = 0;
    if (!mc_write_varint(frame, sizeof(frame), &fo, (int32_t)po) ||
        fo + po > sizeof(frame)) {
        out_set(out, out_len, "minecraft: handshake too large");
        close(fd);
        return -1;
    }
    memcpy(frame + fo, payload, po);
    fo += po;

    if (send_all_timeout(fd, frame, fo, deadline) < 0) {
        out_set(out, out_len, "minecraft: send: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Status request: frame [0x01, 0x00]. */
    {
        uint8_t req[2] = {0x01, 0x00};
        if (send_all_timeout(fd, req, sizeof(req), deadline) < 0) {
            out_set(out, out_len, "minecraft: send: %s", strerror(errno));
            close(fd);
            return -1;
        }
    }

    if (!mc_read_varint_fd(fd, deadline, &frame_len) ||
        frame_len <= 0 || frame_len > P2P_NET_MAX_RESPONSE) {
        out_set(out, out_len, "minecraft: bad status frame length");
        close(fd);
        return -1;
    }

    frame_data = malloc((size_t)frame_len);
    if (!frame_data) {
        out_set(out, out_len, "minecraft: out of memory");
        close(fd);
        return -1;
    }
    if (!mc_read_exact(fd, frame_data, (size_t)frame_len, deadline)) {
        out_set(out, out_len, "minecraft: short status frame");
        free(frame_data);
        close(fd);
        return -1;
    }

    {
        size_t off = 0;
        if (!mc_read_varint_buf(frame_data, (size_t)frame_len, &off,
                                &packet_id) || packet_id != 0x00 ||
            !mc_read_varint_buf(frame_data, (size_t)frame_len, &off,
                                &json_len) ||
            json_len <= 0 || off + (size_t)json_len > (size_t)frame_len) {
            out_set(out, out_len, "minecraft: bad status packet");
            free(frame_data);
            close(fd);
            return -1;
        }

        json = malloc((size_t)json_len + 1);
        if (!json) {
            out_set(out, out_len, "minecraft: out of memory");
            free(frame_data);
            close(fd);
            return -1;
        }
        memcpy(json, frame_data + off, (size_t)json_len);
        json[json_len] = '\0';
        free(frame_data);
    }

    /* Ping/pong for latency.  Failure here is not fatal. */
    {
        uint8_t ping_payload[9];
        uint8_t ping_frame[11];
        uint64_t ping_start = net_now_ms();
        uint64_t ping_value = ping_start;
        size_t pp = 0;
        size_t pf = 0;
        int32_t pong_len = 0;

        ping_payload[pp++] = 0x01;
        for (int k = 7; k >= 0; k--)
            ping_payload[pp++] = (uint8_t)(ping_value >> (k * 8));

        if (mc_write_varint(ping_frame, sizeof(ping_frame), &pf,
                            (int32_t)pp)) {
            memcpy(ping_frame + pf, ping_payload, pp);
            pf += pp;
            if (send_all_timeout(fd, ping_frame, pf, deadline) >= 0 &&
                mc_read_varint_fd(fd, deadline, &pong_len) &&
                pong_len >= 9 && pong_len <= 32) {
                uint8_t pong[32];
                if (mc_read_exact(fd, pong, (size_t)pong_len, deadline)) {
                    size_t off = 0;
                    int32_t pid = -1;
                    if (mc_read_varint_buf(pong, (size_t)pong_len, &off,
                                           &pid) && pid == 0x01 &&
                        off + 8 <= (size_t)pong_len) {
                        latency_ms = (double)(net_now_ms() - ping_start);
                    }
                }
            }
        }
    }

    {
        const char *jend = json + strlen(json);
        const char *desc = NULL;
        const char *desc_end = NULL;

        desc = json_value_after(json, jend, "description", &desc_end);
        if (desc && *desc == '"' && desc_end > desc + 1) {
            json_unescape(desc + 1, (size_t)(desc_end - desc - 2),
                          motd, sizeof(motd));
        } else if (desc && (*desc == '{' || *desc == '[')) {
            json_collect_text(desc, desc_end, motd, sizeof(motd));
        }

        {
            const char *vend = NULL;
            const char *v = json_value_after(json, jend, "version", &vend);
            if (v && *v == '{')
                (void)json_string_after(v, vend, "name",
                                        version, sizeof(version));
        }

        {
            const char *pend = NULL;
            const char *pl = json_value_after(json, jend, "players", &pend);
            if (pl && *pl == '{') {
                (void)json_long_after(pl, pend, "online", &online);
                (void)json_long_after(pl, pend, "max", &max_players);
            }
        }
    }

    out_set(out, out_len, "minecraft %s:%u\n", host, (unsigned)port);
    out_appendf(out, out_len, "version: %s\n", version);
    if (online >= 0 && max_players >= 0)
        out_appendf(out, out_len, "players: %ld/%ld\n",
                    online, max_players);
    else
        out_appendf(out, out_len, "players: ?\n");
    out_appendf(out, out_len, "motd: %s\n",
                motd[0] ? motd : "(empty)");
    if (latency_ms >= 0)
        out_appendf(out, out_len, "latency: %.1f ms\n", latency_ms);
    else
        out_appendf(out, out_len, "latency: unavailable\n");

    free(json);
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Discord webhook                                                           */
/* ------------------------------------------------------------------------- */

static void json_escape(const char *in, char *out, size_t out_len)
{
    size_t j = 0;

    if (!out || out_len == 0) return;

    for (; in && *in && j + 8 < out_len; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = (char)c;
        } else if (c == '\n') {
            out[j++] = '\\';
            out[j++] = 'n';
        } else if (c == '\r') {
            out[j++] = '\\';
            out[j++] = 'r';
        } else if (c == '\t') {
            out[j++] = '\\';
            out[j++] = 't';
        } else if (c < 0x20) {
            j += (size_t)snprintf(out + j, out_len - j, "\\u%04x", c);
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
}

int p2p_net_discord_webhook(const char *webhook_url, const char *content,
                            int timeout_ms, char *out, size_t out_len)
{
    net_url_t u;
    char *escaped = NULL;
    char *body = NULL;
    size_t msg_len;
    int status;

    if (out && out_len) out[0] = '\0';
    if (!webhook_url || !content || !*content) {
        out_set(out, out_len, "discord: URL and message are required");
        return -1;
    }

    if (!parse_url(webhook_url, &u) ||
        strcasecmp(u.scheme, "https") != 0 ||
        !url_host_is_discord(u.host) ||
        strncmp(u.path, "/api/webhooks/", 14) != 0) {
        out_set(out, out_len,
                "discord: only https://discord.com/api/webhooks/... is allowed");
        return -1;
    }

#ifdef P2P_HAVE_CURL
    msg_len = strlen(content);
    if (msg_len > 1900) {
        msg_len = 1900;
        /* Do not split a UTF-8 sequence when truncating. */
        while (msg_len > 0 && ((unsigned char)content[msg_len] & 0xc0) == 0x80)
            msg_len--;
    }

    escaped = malloc(msg_len * 6 + 1);
    if (!escaped) {
        out_set(out, out_len, "discord: out of memory");
        return -1;
    }
    {
        char *tmp = malloc(msg_len + 1);
        if (!tmp) {
            free(escaped);
            out_set(out, out_len, "discord: out of memory");
            return -1;
        }
        memcpy(tmp, content, msg_len);
        tmp[msg_len] = '\0';
        json_escape(tmp, escaped, msg_len * 6 + 1);
        free(tmp);
    }

    body = malloc(strlen(escaped) + 32);
    if (!body) {
        free(escaped);
        out_set(out, out_len, "discord: out of memory");
        return -1;
    }
    snprintf(body, strlen(escaped) + 32, "{\"content\":\"%s\"}", escaped);
    free(escaped);

    status = p2p_net_http_request("POST", webhook_url, "application/json",
                                  body, timeout_ms, out, out_len);
    free(body);

    if (status < 0)
        return -1;
    if (status >= 200 && status < 300) {
        out_set(out, out_len, "discord: delivered (HTTP %d)\n", status);
        return 0;
    }

    out_appendf(out, out_len, "\ndiscord: server returned HTTP %d\n",
                status);
    return -1;
#else
    (void)timeout_ms;
    (void)escaped;
    (void)body;
    (void)msg_len;
    (void)status;
    out_set(out, out_len,
            "discord: HTTPS support missing "
            "(rebuild with libcurl available)");
    return -1;
#endif
}
