#ifndef QV3_FASTHASH_H
#define QV3_FASTHASH_H

#include <stdint.h>
#include <stddef.h>

uint64_t fasthash64(const uint8_t *buf, size_t len, uint64_t seed);
uint32_t fasthash32(const uint8_t *buf, size_t len, uint32_t seed);

#endif
