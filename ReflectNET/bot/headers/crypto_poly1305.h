#pragma once

#include <stdint.h>

void poly1305_mac(uint8_t tag[16], const uint8_t key[32],
                  const uint8_t *msg, int msg_len);
