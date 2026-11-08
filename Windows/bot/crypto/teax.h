#ifndef QV3_TEAX_H
#define QV3_TEAX_H

#include <stdint.h>
#include <stddef.h>

/* in-place encrypt/decrypt using server EncKey */
void teax_encrypt(uint8_t *data, size_t len);

#endif
