#pragma once
#include <stdint.h>

/* Anti-extraction key schedule: returns OBFK slot values through
 * computation chains that defeat constant propagation, pattern
 * matching, and static analysis (radare2/Ghidra/IDA). */
uint32_t ks_get(int slot);
