#pragma once

#include "includes.h"

void redirect_handle(char *buf, int len);
BOOL redirect_take(ipv4_t *addr, port_t *port);
