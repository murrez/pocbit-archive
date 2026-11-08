#pragma once

#include <stdint.h>

#define ENCRYPT_KEY_LEN 32
#define ENCRYPT_NONCE_LEN 12
#define ENCRYPT_TAG_LEN 16

void chacha20_init(uint32_t state[16], const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]);
void chacha20_block(uint32_t state[16], uint8_t out[64]);
void chacha20_encrypt(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], const uint8_t *in, uint8_t *out, int len);

void poly1305_mac(uint8_t tag[16], const uint8_t key[32], const uint8_t *msg, int msg_len);

void set_nonce_prefix(const uint8_t prefix[4]);

int encrypt_packet(const uint8_t key[32], uint32_t seq, const uint8_t *plain, int plain_len, uint8_t *out, int *out_len);
int decrypt_packet(const uint8_t key[32], uint32_t seq, const uint8_t *in, int in_len, uint8_t *plain, int *plain_len);
