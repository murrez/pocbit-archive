#pragma once

#include <stdint.h>

/* Minecraft login encryption: RSA/PKCS1 + AES/CFB8 */
int mc_rsa_encrypt(const uint8_t *der, int der_len,
                   const uint8_t *plain, int plain_len,
                   uint8_t *out, int out_cap);

void mc_aes_cfb8_crypt(const uint8_t key[16], uint8_t iv[16],
                       uint8_t *data, int len);

int mc_parse_encryption_request(const uint8_t *payload, int len,
                              uint8_t *pubkey_out, int pubkey_cap,
                              uint8_t *verify_token, int *verify_len);

int mc_build_encryption_response(const uint8_t *shared_secret,
                                 const uint8_t *verify_token, int verify_len,
                                 const uint8_t *der_pubkey, int der_len,
                                 uint8_t *out, int out_cap);
