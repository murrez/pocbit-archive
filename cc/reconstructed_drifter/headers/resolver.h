#ifndef DRIFTER_RESOLVER_H
#define DRIFTER_RESOLVER_H

#include "drifter.h"

#ifdef __cplusplus
extern "C" {
#endif

void address_list_free(AddressList *list);

AddressList *dns_resolve(AddressList *out, const char *name,
                         int alternate_server, int raw_address);

AddressList *resolver_choose_addresses(AddressList *out);

uint32_t resolver_discover_local_address(void);

char *read_line(int fd, char *buffer, int capacity);

uint32_t resolver_select_dns_server(void);

#ifdef __cplusplus
}
#endif

#endif
