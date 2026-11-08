#ifndef DRIFTER_CONFIG_H
#define DRIFTER_CONFIG_H

#include <stdint.h>

int config_set(int32_t index, const char *value);

int config_append_entry(int32_t index, const void *data, int32_t length);

int config_initialize(void);

int config_bootstrap(void);

#endif
