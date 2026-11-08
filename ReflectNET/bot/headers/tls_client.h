#pragma once

#include <stdint.h>

typedef struct {
    uint8_t priv[32];
    uint8_t pub[32];
    uint8_t srv_pub[32];
    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t client_app_key[32];
    uint8_t client_app_iv[12];
    uint64_t app_seq;
    int ready;
} tls_client_t;

void tls_client_reset(tls_client_t *s);
int tls_client_handshake(tls_client_t *s, int fd, const char *sni, int timeout_ms);
int tls_client_send(tls_client_t *s, int fd, const uint8_t *data, int len);
