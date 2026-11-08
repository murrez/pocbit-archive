#pragma once

#include "includes.h"
#include "attack.h"

void attack_tls_bomb(uint8_t targs_len, struct attack_target *targs,
                     uint8_t opts_len, struct attack_option *opts);
