#include "rand.h"
#include <stddef.h>
#include <stdlib.h>

void generate_random_payload(char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        data[i] = (char)(rand() % 256);  
    }
}