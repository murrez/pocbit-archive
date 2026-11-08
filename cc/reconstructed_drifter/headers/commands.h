#ifndef DRIFTER_COMMANDS_H
#define DRIFTER_COMMANDS_H

#include "drifter.h"

#include <stdint.h>

uint32_t commands_process_config(char *text);

uint32_t commands_parse_targets(char *target_list);

uint32_t commands_dispatch(char *text);

#endif
