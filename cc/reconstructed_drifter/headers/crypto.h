#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

int config_crypt_buffer(char *data, int32_t length);

int config_decrypt_entry(int index);
int config_encrypt_entry(int index);

#endif
