#define _GNU_SOURCE

#include "drifter.h"
#include "crypto.h"
#include "config_data.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ADMIN_PORT 2222
#define MAX_CLIENTS 16
#define MAX_PACKET 2048
#define INPUT_LIMIT 512

static const uint16_t mock_ports[] = {
    23004, 37610, 25632, 7061, 34532,
    32505, 36275, 36605, 58234, 44308
};

typedef struct MockClient {
    int fd;
    int id;
    int greeted;
} MockClient;

Blob *g_config;
static MockClient clients[MAX_CLIENTS];
static int next_client_id = 1;
static atomic_int running = 1;
static FILE *log_file;
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t crypto_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void log_event(const char *format, ...)
{
    char timestamp[32];
    time_t now = time(NULL);
    struct tm local;
    va_list arguments;

    localtime_r(&now, &local);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &local);
    pthread_mutex_lock(&log_mutex);
    fprintf(stdout, "[%s] ", timestamp);
    va_start(arguments, format);
    vfprintf(stdout, format, arguments);
    va_end(arguments);
    fputc('\n', stdout);
    fflush(stdout);
    if (log_file != NULL) {
        fprintf(log_file, "[%s] ", timestamp);
        va_start(arguments, format);
        vfprintf(log_file, format, arguments);
        va_end(arguments);
        fputc('\n', log_file);
        fflush(log_file);
    }
    pthread_mutex_unlock(&log_mutex);
}

static void log_bytes(const char *prefix, const unsigned char *data, size_t length)
{
    char text[513];
    size_t output = 0;
    size_t limit = length < 128 ? length : 128;

    for (size_t i = 0; i < limit && output + 4 < sizeof(text); ++i) {
        unsigned char c = data[i];
        if (c >= 0x20 && c <= 0x7e && c != '\\') {
            text[output++] = (char)c;
        } else {
            int written = snprintf(text + output, sizeof(text) - output,
                                   "\\x%02x", c);
            if (written < 0)
                break;
            output += (size_t)written;
        }
    }
    text[output] = '\0';
    log_event("%s%s (%zu bytes)%s", prefix, text, length,
              length > limit ? " ..." : "");
}

static int load_configuration(void)
{
    g_config = calloc(76, sizeof(*g_config));
    if (g_config == NULL)
        return -1;
    for (size_t i = 0; i < config_data_entry_count; ++i) {
        const ConfigDataEntry *entry = &config_data_entries[i];
        char *copy = calloc((size_t)entry->length + 1, 1);
        if (copy == NULL)
            return -1;
        memcpy(copy, entry->data, (size_t)entry->length);
        g_config[entry->index].data = copy;
        g_config[entry->index].length = (size_t)entry->length;
    }
    return 0;
}

static void free_configuration(void)
{
    if (g_config == NULL)
        return;
    for (size_t i = 0; i < config_data_entry_count; ++i)
        free(g_config[config_data_entries[i].index].data);
    free(g_config);
    g_config = NULL;
}

static int ensure_users_file(void)
{
    if (access("users.txt", R_OK) == 0)
        return 0;
    FILE *users = fopen("users.txt", "w");
    if (users == NULL)
        return -1;
    fputs("admin:test123!\n", users);
    if (fclose(users) != 0)
        return -1;
    chmod("users.txt", 0600);
    log_event("created users.txt with the test admin account");
    return 0;
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int create_listener(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    int enabled = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(fd, 8) < 0 || set_nonblocking(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void remove_client(size_t index)
{
    if (index >= MAX_CLIENTS || clients[index].fd < 0)
        return;
    log_event("client %d disconnected", clients[index].id);
    close(clients[index].fd);
    clients[index].fd = -1;
    clients[index].id = 0;
    clients[index].greeted = 0;
}

static void accept_client(int listener)
{
    int fd = accept(listener, NULL, NULL);
    if (fd < 0)
        return;
    if (set_nonblocking(fd) < 0) {
        close(fd);
        return;
    }

    pthread_mutex_lock(&clients_mutex);
    size_t slot = MAX_CLIENTS;
    for (size_t i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].fd < 0) {
            slot = i;
            break;
        }
    }
    if (slot == MAX_CLIENTS) {
        pthread_mutex_unlock(&clients_mutex);
        close(fd);
        log_event("connection rejected: client table full");
        return;
    }
    clients[slot].fd = fd;
    clients[slot].id = next_client_id++;
    clients[slot].greeted = 0;
    int id = clients[slot].id;
    pthread_mutex_unlock(&clients_mutex);
    log_event("client %d connected", id);
}

static void receive_client(size_t index)
{
    unsigned char buffer[MAX_PACKET + 1];
    pthread_mutex_lock(&clients_mutex);
    if (index >= MAX_CLIENTS || clients[index].fd < 0) {
        pthread_mutex_unlock(&clients_mutex);
        return;
    }

    ssize_t received = recv(clients[index].fd, buffer, MAX_PACKET, 0);
    if (received <= 0) {
        remove_client(index);
        pthread_mutex_unlock(&clients_mutex);
        return;
    }

    int id = clients[index].id;
    char prefix[64];
    if (!clients[index].greeted) {
        pthread_mutex_lock(&crypto_mutex);
        config_crypt_buffer((char *)buffer, (int32_t)received);
        pthread_mutex_unlock(&crypto_mutex);
        clients[index].greeted = 1;
        snprintf(prefix, sizeof(prefix), "client %d greeting: ", id);
        log_bytes(prefix, buffer, (size_t)received);
    } else {
        snprintf(prefix, sizeof(prefix), "client %d data: ", id);
        log_bytes(prefix, buffer, (size_t)received);
    }
    pthread_mutex_unlock(&clients_mutex);
}

static void *mock_server_main(void *unused)
{
    int listeners[10];
    (void)unused;
    for (size_t i = 0; i < 10; ++i) {
        listeners[i] = create_listener(mock_ports[i]);
        if (listeners[i] < 0) {
            log_event("failed to bind mock port %u: %s", mock_ports[i],
                      strerror(errno));
            for (size_t j = 0; j < i; ++j)
                close(listeners[j]);
            return NULL;
        }
    }
    log_event("raw mock protocol listening on all ten client ports");

    while (atomic_load(&running)) {
        struct pollfd descriptors[10 + MAX_CLIENTS];
        size_t mappings[10 + MAX_CLIENTS];
        nfds_t count = 0;
        for (size_t i = 0; i < 10; ++i) {
            descriptors[count].fd = listeners[i];
            descriptors[count].events = POLLIN;
            descriptors[count].revents = 0;
            mappings[count] = i;
            ++count;
        }

        pthread_mutex_lock(&clients_mutex);
        for (size_t i = 0; i < MAX_CLIENTS; ++i) {
            if (clients[i].fd >= 0) {
                descriptors[count].fd = clients[i].fd;
                descriptors[count].events = POLLIN;
                descriptors[count].revents = 0;
                mappings[count] = i + 10;
                ++count;
            }
        }
        pthread_mutex_unlock(&clients_mutex);

        int ready = poll(descriptors, count, 250);
        if (ready <= 0)
            continue;
        for (nfds_t i = 0; i < count; ++i) {
            if (!(descriptors[i].revents & (POLLIN | POLLERR | POLLHUP)))
                continue;
            if (mappings[i] < 10) {
                if (descriptors[i].revents & POLLIN)
                    accept_client(descriptors[i].fd);
            } else {
                size_t client_index = mappings[i] - 10;
                if (descriptors[i].revents & POLLIN) {
                    receive_client(client_index);
                } else {
                    pthread_mutex_lock(&clients_mutex);
                    remove_client(client_index);
                    pthread_mutex_unlock(&clients_mutex);
                }
            }
        }
    }

    for (size_t i = 0; i < 10; ++i)
        close(listeners[i]);
    pthread_mutex_lock(&clients_mutex);
    for (size_t i = 0; i < MAX_CLIENTS; ++i)
        remove_client(i);
    pthread_mutex_unlock(&clients_mutex);
    return NULL;
}

static void list_clients(char *output, size_t capacity)
{
    size_t used = 0;
    output[0] = '\0';
    pthread_mutex_lock(&clients_mutex);
    for (size_t i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].fd >= 0 && used + 64 < capacity) {
            int written = snprintf(output + used, capacity - used,
                                   "id=%d greeted=%s\n", clients[i].id,
                                   clients[i].greeted ? "yes" : "no");
            if (written > 0)
                used += (size_t)written;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    if (used == 0)
        snprintf(output, capacity, "No connected clients.\n");
}

typedef enum SafeCommand {
    COMMAND_PING,
    COMMAND_UD,
    COMMAND_WHITELIST
} SafeCommand;

static int send_all(int fd, const char *data, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t sent = send(fd, data + offset, length - offset, MSG_NOSIGNAL);
        if (sent > 0) {
            offset += (size_t)sent;
            continue;
        }
        if (sent == 0)
            return -1;
        if (errno == EINTR)
            continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return -1;
        struct pollfd writable;
        writable.fd = fd;
        writable.events = POLLOUT;
        writable.revents = 0;
        int ready;
        do {
            ready = poll(&writable, 1, 2000);
        } while (ready < 0 && errno == EINTR);
        if (ready <= 0)
            return -1;
    }
    return 0;
}

static int send_safe_command(int id, SafeCommand command, const char *payload)
{
    char buffer[INPUT_LIMIT];
    const char *data = buffer;
    size_t length;
    int result = 0;

    if (command == COMMAND_PING) {
        data = g_config[52].data;
        length = g_config[52].length;
    } else {
        int written = snprintf(buffer, sizeof(buffer), "%s %s",
                               command == COMMAND_UD ? "ud" : "whitelist",
                               payload);
        if (written < 0 || (size_t)written >= sizeof(buffer))
            return -3;
        length = (size_t)written;
        pthread_mutex_lock(&crypto_mutex);
        config_crypt_buffer(buffer, (int32_t)length);
        pthread_mutex_unlock(&crypto_mutex);
    }

    pthread_mutex_lock(&clients_mutex);
    size_t slot = MAX_CLIENTS;
    for (size_t i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].fd >= 0 && clients[i].id == id) {
            slot = i;
            break;
        }
    }
    if (slot == MAX_CLIENTS) {
        result = -1;
    } else if (!clients[slot].greeted) {
        result = -4;
    } else {
        result = send_all(clients[slot].fd, data, length);
        if (result != 0)
            result = -2;
    }
    pthread_mutex_unlock(&clients_mutex);

    if (result == 0)
        log_event("sent command to client %d", id);
    else
        log_event("command to client %d failed (%d)", id, result);
    return result;
}

static int valid_ud_payload(const char *payload)
{
    char a[64], b[64], c[64], d[64], e[64], extra[2];
    return sscanf(payload, "%63s %63s %63s %63s %63s %1s",
                  a, b, c, d, e, extra) == 5;
}

static int valid_whitelist_payload(const char *payload)
{
    char value[128], extra[2];
    return sscanf(payload, "%127s %1s", value, extra) == 1;
}

static int credentials_valid(const char *username, const char *password)
{
    FILE *users = fopen("users.txt", "r");
    char line[256];
    int valid = 0;
    if (users == NULL || username == NULL || password == NULL) {
        if (users != NULL)
            fclose(users);
        return 0;
    }
    while (fgets(line, sizeof(line), users) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        char *separator = strchr(line, ':');
        if (separator == NULL)
            continue;
        *separator = '\0';
        if (strcmp(line, username) == 0 && strcmp(separator + 1, password) == 0) {
            valid = 1;
            break;
        }
    }
    fclose(users);
    return valid;
}

static int write_text(int fd, const char *text)
{
    size_t remaining = strlen(text);
    const char *cursor = text;
    while (remaining > 0) {
        ssize_t written = send(fd, cursor, remaining, MSG_NOSIGNAL);
        if (written <= 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        cursor += written;
        remaining -= (size_t)written;
    }
    return 0;
}

static ssize_t read_text_line(int fd, char *buffer, size_t capacity,
                              int *skip_lf, int echo)
{
    size_t used = 0;
    int truncated = 0;
    int first_character = 1;

    for (;;) {
        char c;
        ssize_t received = recv(fd, &c, 1, 0);
        if (received <= 0)
            return -1;
        if (first_character && *skip_lf) {
            *skip_lf = 0;
            if (c == '\n')
                continue;
        }
        first_character = 0;
        if (c == '\r') {
            *skip_lf = 1;
            if (echo)
                write_text(fd, "\r\n");
            break;
        }
        if (c == '\n') {
            *skip_lf = 0;
            if (echo)
                write_text(fd, "\r\n");
            break;
        }
        if (c == '\b' || c == 0x7f) {
            if (used > 0) {
                --used;
                if (echo)
                    write_text(fd, "\b \b");
            }
            continue;
        }
        if (c == '\t')
            c = ' ';
        if ((unsigned char)c < 0x20 || (unsigned char)c == 0x7f)
            continue;
        if (used + 1 < capacity) {
            buffer[used++] = c;
            if (echo) {
                char text[2] = {c, '\0'};
                write_text(fd, text);
            }
        } else {
            truncated = 1;
        }
    }
    if (truncated) {
        buffer[0] = '\0';
        return -2;
    }
    buffer[used] = '\0';
    return (ssize_t)used;
}

static void show_banner(int fd)
{
    write_text(fd,
        "  Raw Loopback Test Server\r\n"
        "  commands: ping / ud / whitelist\r\n"
        "Type 'help' for commands.\r\n\r\n");
}

static void handle_send(int fd, char *arguments)
{
    char *end;
    long id = strtol(arguments, &end, 10);
    if (end == arguments || id <= 0 || id > 0x7fffffff) {
        write_text(fd, "Usage: send <id> ping|ud ...|whitelist ...\r\n");
        return;
    }
    while (*end == ' ')
        ++end;

    if (strcmp(end, "ping") == 0) {
        int result = send_safe_command((int)id, COMMAND_PING, NULL);
        write_text(fd, result == 0 ? "Ping sent.\r\n" :
                   "Ping failed: unknown client or send error.\r\n");
        return;
    }
    if (strncmp(end, "ud ", 3) == 0) {
        const char *payload = end + 3;
        if (!valid_ud_payload(payload)) {
            write_text(fd, "ud requires exactly five values.\r\n");
            return;
        }
        int result = send_safe_command((int)id, COMMAND_UD, payload);
        write_text(fd, result == 0 ? "ud sent.\r\n" :
                   "ud failed: unknown client or send error.\r\n");
        return;
    }
    if (strncmp(end, "whitelist ", 10) == 0) {
        const char *payload = end + 10;
        if (!valid_whitelist_payload(payload)) {
            write_text(fd, "whitelist requires exactly one value.\r\n");
            return;
        }
        int result = send_safe_command((int)id, COMMAND_WHITELIST, payload);
        write_text(fd, result == 0 ? "whitelist sent.\r\n" :
                   "whitelist failed: unknown client or send error.\r\n");
        return;
    }

    log_event("disabled/unknown command rejected for client %ld", id);
    write_text(fd,
        "Rejected: only ping, ud, and whitelist are enabled. "
        "Flood opcodes and arbitrary commands are disabled.\r\n");
}

static void handle_admin(int fd)
{
    char username[128];
    char password[128];
    char input[INPUT_LIMIT];
    int skip_lf = 0;

    write_text(fd, "Login: ");
    if (read_text_line(fd, username, sizeof(username), &skip_lf, 1) < 0)
        return;
    write_text(fd, "Password: ");
    if (read_text_line(fd, password, sizeof(password), &skip_lf, 0) < 0)
        return;
    write_text(fd, "\r\n");

    if (!credentials_valid(username, password)) {
        log_event("raw admin login rejected for %s", username);
        write_text(fd, "Authentication failed.\r\n");
        return;
    }
    log_event("raw admin login accepted for %s", username);
    show_banner(fd);

    for (;;) {
        write_text(fd, "raw-safe> ");
        ssize_t line_result = read_text_line(fd, input, sizeof(input),
                                             &skip_lf, 1);
        if (line_result == -2) {
            write_text(fd, "Input line too long; rejected.\r\n");
            continue;
        }
        if (line_result < 0)
            break;
        if (*input == '\0')
            continue;
        if (strcmp(input, "exit") == 0 || strcmp(input, "quit") == 0)
            break;
        if (strcmp(input, "help") == 0) {
            write_text(fd,
                "help                         Show this help\r\n"
                "banner                       Show the login banner\r\n"
                "clients                      List mock clients\r\n"
                "send <id> ping               Send entry-52 ping\r\n"
                "send <id> ud v1 v2 v3 v4 v5  Send config-test command\r\n"
                "send <id> whitelist value    Send whitelist-test command\r\n"
                "exit                         Disconnect\r\n"
                "Flood opcodes and shell execution are disabled.\r\n");
        } else if (strcmp(input, "banner") == 0) {
            show_banner(fd);
        } else if (strcmp(input, "clients") == 0) {
            char listing[2048];
            list_clients(listing, sizeof(listing));
            write_text(fd, listing);
        } else if (strncmp(input, "send ", 5) == 0) {
            handle_send(fd, input + 5);
        } else {
            log_event("unknown raw command rejected: %s", input);
            write_text(fd, "Unknown command. Type 'help'.\r\n");
        }
    }
    log_event("raw admin session closed");
}

static int run_admin_server(void)
{
    int listener = create_listener(ADMIN_PORT);
    if (listener < 0) {
        log_event("raw admin bind/listen failed: %s", strerror(errno));
        return -1;
    }
    log_event("raw admin listening on 127.0.0.1:%d", ADMIN_PORT);

    while (atomic_load(&running)) {
        int fd = accept(listener, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            usleep(100000);
            continue;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0)
            (void)fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        handle_admin(fd);
        close(fd);
    }
    close(listener);
    return 0;
}

int main(void)
{
    pthread_t mock_thread;
    signal(SIGPIPE, SIG_IGN);
    log_file = fopen("server.log", "a");
    log_event("raw loopback server starting");

    if (ensure_users_file() != 0 || load_configuration() != 0) {
        log_event("startup initialization failed");
        free_configuration();
        if (log_file != NULL)
            fclose(log_file);
        return 1;
    }
    for (size_t i = 0; i < MAX_CLIENTS; ++i)
        clients[i].fd = -1;

    if (pthread_create(&mock_thread, NULL, mock_server_main, NULL) != 0) {
        log_event("failed to start mock protocol thread");
        free_configuration();
        if (log_file != NULL)
            fclose(log_file);
        return 1;
    }

    int result = run_admin_server();
    atomic_store(&running, 0);
    pthread_join(mock_thread, NULL);
    free_configuration();
    log_event("raw loopback server stopped");
    if (log_file != NULL)
        fclose(log_file);
    return result;
}
