#ifndef PRNG_H
#define PRNG_H

#include <stdint.h>

uint32_t prng_next(void);
void prng_seed(void);
int32_t prng_range(int32_t min, int32_t max);
void prng_hex(char *out, int32_t length);
void prng_bytes(void *out, int32_t length);
void prng_alphanumeric(char *out, int32_t length);
uint32_t prng_ipv4(void);

#endif
