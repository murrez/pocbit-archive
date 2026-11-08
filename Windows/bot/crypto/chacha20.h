#ifndef QV3_CHACHA20_H
#define QV3_CHACHA20_H

#include <stdint.h>
#include <stddef.h>

/* counter is the 32-bit block counter, nonce is 12 bytes, key is 32 bytes */
void chacha20_xor(const uint8_t *key, uint32_t counter, const uint8_t *nonce,
                  const uint8_t *in, uint8_t *out, size_t len);
void chacha20_encrypt(const uint8_t *key, uint32_t counter, const uint8_t *nonce,
                      const uint8_t *in, uint8_t *out, size_t len);

#endif
