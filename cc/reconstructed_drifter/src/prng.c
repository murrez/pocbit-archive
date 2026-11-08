#include "prng.h"
#include "drifter.h"

#include <stdlib.h>
#include <time.h>
#include <unistd.h>

uint32_t g_prng_state[4] = {0u, 0u, 0u, 0u};

uint32_t prng_next(void)
{
    uint32_t t = g_prng_state[0] ^ (g_prng_state[0] << 11);
    uint32_t value = g_prng_state[3] ^ (g_prng_state[3] >> 19)
        ^ t ^ (t >> 8);

    g_prng_state[0] = g_prng_state[1];
    g_prng_state[1] = g_prng_state[2];
    g_prng_state[2] = g_prng_state[3];
    g_prng_state[3] = value;
    return value;
}

void prng_seed(void)
{
    uint32_t clock_value;
    uint32_t pid;

    g_prng_state[0] = (uint32_t)time(NULL);
    pid = (uint32_t)getpid();
    g_prng_state[1] = (uint32_t)getppid() ^ pid;
    clock_value = (uint32_t)clock();
    g_prng_state[3] = clock_value ^ g_prng_state[1];
    g_prng_state[2] = clock_value;
}

int32_t prng_range(int32_t min, int32_t max)
{
    uint32_t span = (uint32_t)max - (uint32_t)min + 1u;
    return (int32_t)((uint32_t)min + (prng_next() % span));
}

void prng_hex(char *out, int32_t length)
{
    static const char digits[] = "0123456789abcdef";
    int32_t i;

    for (i = 0; i < length; ++i) {
        out[i] = digits[prng_next() & 0x0fu];
    }
}

void prng_bytes(void *out, int32_t length)
{
    uint8_t *bytes = (uint8_t *)out;

    while (length > 0) {
        uint32_t value = prng_next();

        if (length > 3) {
            bytes[0] = (uint8_t)value;
            bytes[1] = (uint8_t)(value >> 8);
            bytes[2] = (uint8_t)(value >> 16);
            bytes[3] = (uint8_t)(value >> 24);
            bytes += 4;
            length -= 4;
        } else if (length == 1) {
            bytes[0] = (uint8_t)value;
            break;
        } else {
            bytes[0] = (uint8_t)value;
            bytes[1] = (uint8_t)(value >> 8);
            bytes += 2;
            length -= 2;
        }
    }
}

void prng_alphanumeric(char *out, int32_t length)
{
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    int32_t i;

    for (i = 0; i < length; ++i) {
        out[i] = alphabet[prng_next() % 36u];
    }
    out[length] = '\0';
}

uint32_t prng_ipv4(void)
{
    switch (prng_next() % 5u) {
    case 0u:
        return 0x08080808u;
    case 1u:
        return 0x01010101u;
    case 2u:
        return 0xdede43d0u;
    case 3u:
        return 0x09090909u;
    case 4u:
        return 0x0808584du;
    default:
        return 0u;
    }
}
