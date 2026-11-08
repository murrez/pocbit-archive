#pragma once

#include <stdint.h>

void x25519_gen_keypair(uint8_t pub[32], uint8_t priv[32]);
void x25519_scalarmult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
