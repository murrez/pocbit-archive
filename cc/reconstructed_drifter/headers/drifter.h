#ifndef DRIFTER_H
#define DRIFTER_H

#include <stddef.h>
#include <stdint.h>

typedef struct Blob {
    char *data;
    size_t length;
} Blob;

typedef struct Target {
    char address[16];
    int32_t prefix_length;
} Target;

typedef struct AddressList {
    uint32_t *items;
    int32_t count;
} AddressList;

#define DRIFTER_MAX_TARGETS 16
#define DRIFTER_PID_BITMAP_BYTES 0x80000u

extern Blob *g_config;
extern Target g_targets[DRIFTER_MAX_TARGETS];
extern uint32_t g_target_count;

extern uint32_t g_prng_state[4];
extern uint32_t g_bootstrap_address;
extern uint32_t g_dns_server_address;
extern uint32_t g_local_address;

extern uint32_t g_process_scan_counter;
extern uint8_t g_pid_bitmap[DRIFTER_PID_BITMAP_BYTES];

#endif
