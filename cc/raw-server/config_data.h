#ifndef DRIFTER_CONFIG_DATA_H
#define DRIFTER_CONFIG_DATA_H

#include <stddef.h>
#include <stdint.h>

typedef struct ConfigDataEntry {
    int32_t index;
    const unsigned char *data;
    int32_t length;
    uint32_t source_address;
} ConfigDataEntry;

extern const ConfigDataEntry config_data_entries[];
extern const size_t config_data_entry_count;

#endif
