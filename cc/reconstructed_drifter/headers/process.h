#ifndef DRIFTER_PROCESS_H
#define DRIFTER_PROCESS_H

#include "drifter.h"

#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct StringList {
    char **items;
    int32_t count;
} StringList;

void process_init_hook(void);
void process_fini_hook(void);

DIR *process_scan_and_kill(void);

pid_t process_launch_worker(void);

char *string_duplicate(const char *text);
StringList *string_split(const char *text, const char *delimiters);
void *memory_find_case_insensitive(const void *haystack, size_t haystack_length,
                                   const void *needle, size_t needle_length);

#endif
