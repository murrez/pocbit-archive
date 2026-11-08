#pragma once

#include "includes.h"
#include "attack.h"

int tls_build_client_hello(uint8_t *buf, const char *sni, int pad_len,
                           uint8_t pub_out[32], uint8_t priv_out[32]);

void attack_tls_bomb(uint8_t targs_len, struct attack_target *targs,
                     uint8_t opts_len, struct attack_option *opts);
