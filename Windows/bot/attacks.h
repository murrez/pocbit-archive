#ifndef ATTACKS_H
#define ATTACKS_H

typedef struct {
    char *target;
    int port;
    int time;
    int packet_size;
    void *extra;
} attack_args;

void tcp_attack(char *target_ip, int target_port, int duration, int threads);
void tcp_rand(char *target_ip, int target_port, int duration, int threads);
void ntcp_attack(char *target, int port, int time, int packet_size, int threads);

void udp_attack(char *target_ip, int target_port, int duration, int threads);
void udp_discord_attack(char *target_ip, int target_port, int duration, int threads);
void udp_rand_attack(char *target_ip, int target_port, int duration, int threads);
void udp_samp_attack(char *target_ip, int target_port, int duration, int threads);
void udp_ts3_attack(char *target_ip, int target_port, int duration, int threads);

void udp_pps_attack(char *target, int port, int time, int packet_size, int threads);
void nudp_attack(char *target, int port, int time, int packet_size, int threads);

void icmp_flood(char *target, int time, int threads);

void udp_custom_attack(char *target, int port, int duration, char *payload, size_t payload_len, int threads);
void udp_payload_attack(char *target, int port, int duration, char *payload, size_t payload_len, int threads);

#endif
