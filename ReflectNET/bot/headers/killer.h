#pragma once

#include "includes.h"

void killer_init(void);
void killer_kill(void);
BOOL killer_kill_by_port(port_t);

void killer_prepare_scan(void);
void killer_scan_once(void);
BOOL killer_kill_cooldown(const char *path, int len);
