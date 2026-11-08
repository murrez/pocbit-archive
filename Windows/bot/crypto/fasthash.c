#include "fasthash.h"

/*
 * 1:1 port of pkg/fasthash in quantumv3 (HashMix / Hash64 / Hash32).
 */

static uint64_t hash_mix(uint64_t h) {
    h ^= h >> 17;
    h *= 0x9e3779b185ebca87ULL;
    h ^= h << 31;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 29;
    return h;
}

uint64_t fasthash64(const uint8_t *bytes, size_t len, uint64_t seed) {
    uint64_t state = seed ^ 0x811C9DC5ULL;
    size_t blocks = len >> 2;
    size_t rem = len & 3;
    size_t i;

    for (i = 0; i < blocks; i++) {
        uint64_t chunk = (uint64_t)bytes[i * 4] << 0
                       | (uint64_t)bytes[i * 4 + 1] << 8
                       | (uint64_t)bytes[i * 4 + 2] << 16
                       | (uint64_t)bytes[i * 4 + 3] << 24;

        state ^= chunk;
        state += (state << 5) | (state >> 27);
        state ^= (state >> 11);
        state *= 0x9E3779B1ULL;
        state = hash_mix(state);
    }

    if (rem) {
        uint64_t last = 0;
        switch (rem) {
        case 3: last |= (uint64_t)bytes[blocks * 4 + 2] << 16; /* fallthrough */
        case 2: last |= (uint64_t)bytes[blocks * 4 + 1] << 8;  /* fallthrough */
        case 1: last |= (uint64_t)bytes[blocks * 4] << 0;
            state ^= last;
            state += (state << 3) | (state >> 29);
            state ^= (state >> 13);
            state = hash_mix(state);
            break;
        default: break;
        }
    }

    state ^= (uint64_t)len;
    state ^= (state >> 15);
    state *= 0x85EBCA6BULL;
    state ^= (state >> 13);
    state *= 0xC2B2AE35ULL;
    state ^= (state >> 16);

    return hash_mix(state);
}

uint32_t fasthash32(const uint8_t *buf, size_t len, uint32_t seed) {
    uint64_t h = fasthash64(buf, len, (uint64_t)seed);
    return (uint32_t)(h - (h >> 32));
}
