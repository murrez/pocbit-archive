/* FILE: flood.h */
#ifndef DRIFTER_FLOOD_H
#define DRIFTER_FLOOD_H

#include "drifter.h"

#include <stdint.h>
#include <sys/types.h>

uint16_t flood_checksum16(const void *data, int32_t length);

uint16_t flood_tcp_checksum(const uint8_t *ipv4_header,
                            const uint8_t *tcp_segment,
                            uint32_t segment_length_network,
                            int32_t segment_length);

uint32_t flood_write_tcp_timestamp(uint8_t *option);

pid_t flood_spawn_watchdog(int32_t delay_seconds);

int32_t flood_udp_hex(Target *targets, int32_t target_count,
                      int32_t watchdog_delay, uint32_t destination_port,
                      uint16_t source_port, uint16_t payload_length,
                      int32_t round_delay_us, const void *payload);

int32_t flood_udp_bytes(Target *targets, int32_t target_count,
                        int32_t watchdog_delay, uint32_t destination_port,
                        uint16_t source_port, uint16_t payload_length,
                        int32_t round_delay_us, const void *payload);

void flood_tcp_connect(const char *target_address, int32_t watchdog_delay,
                       int32_t destination_port, uint16_t payload_length,
                       int32_t io_delay_us, const void *payload) __attribute__((noreturn));

int32_t flood_tcp_syn(Target *targets, int32_t target_count,
                      int32_t watchdog_delay, uint32_t destination_port,
                      uint16_t source_port, int32_t packet_delay_us);

int32_t flood_icmp_echo(Target *targets, int32_t target_count,
                        int32_t watchdog_delay, int32_t destination_port,
                        uint16_t payload_length, int32_t packet_delay_us,
                        const void *payload);

int32_t flood_tcp_ack(Target *targets, int32_t target_count,
                      int32_t watchdog_delay, uint32_t destination_port,
                      uint16_t source_port, uint16_t payload_length,
                      int32_t packet_delay_us, const void *payload);

int32_t flood_tcp_push_ack(Target *targets, int32_t target_count,
                           int32_t watchdog_delay, uint32_t destination_port,
                           uint16_t source_port, uint16_t payload_length,
                           int32_t packet_delay_us, const void *payload);

int32_t flood_udp_raw(Target *targets, int32_t target_count,
                      int32_t watchdog_delay, uint32_t destination_port,
                      uint16_t source_port, uint16_t payload_length,
                      int32_t packet_delay_us, const void *payload);

#endif
