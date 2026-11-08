#include <stdint.h>
#include <string.h>
#include "keysched.h"

/* ---------------------------------------------------------------
 * Anti-extraction key schedule
 *
 * Each OBFK constant is derived through a multi-step computation
 * that uses volatile intermediates, runtime address mixing (which
 * cancels out), and unique arithmetic paths per slot. Dead branches
 * with fake constants pollute the disassembly.
 * --------------------------------------------------------------- */

/* Anchor function whose address we mix in (and cancel out).
 * __attribute__((noinline)) ensures it has a stable, distinct address. */
static __attribute__((noinline)) uint32_t ks_anchor(uint32_t x)
{
    volatile uint32_t v = x;
    return v;
}

/* Second anchor in a different code region */
static __attribute__((noinline)) uint32_t ks_anchor2(uint32_t x)
{
    volatile uint32_t v = x;
    v ^= 0;
    return v;
}

/* Fake constants that appear in dead branches — plausible-looking
 * values an analyst might try. Different per slot. */
static const uint32_t decoy_pool[16] = {
    0xDEADBEEFU, 0xCAFEBABEU, 0x8BADF00DU, 0xFEEDFACEU,
    0xC0FFEE00U, 0xBADC0DEEU, 0x0B00B135U, 0xD15EA5E0U,
    0x13371337U, 0xABCD1234U, 0x55AA55AAU, 0x12345678U,
    0x9E3779B9U, 0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U,
};

/* Opaque predicate: always returns 1, but a static analyzer
 * cannot prove it without solving the identity. */
static __attribute__((noinline)) int ks_opaque(uint32_t v)
{
    volatile uint32_t a = v;
    volatile uint32_t b = a * 3;
    /* 3v mod 3 == 0 always, so (b%3 == 0) is always true */
    return (b % 3) == 0;
}

/* Address-derived salt: XOR in the function pointer address bits,
 * then XOR them back out so the result is unchanged. This forces
 * the disassembler to track pointer arithmetic. */
static __attribute__((noinline)) uint32_t addr_mix(uint32_t val)
{
    volatile uintptr_t fptr = (uintptr_t)(void *)ks_anchor;
    volatile uint32_t salt = (uint32_t)(fptr & 0xFFFFFFFFU);
    volatile uint32_t mixed = val ^ salt;
    /* Cancel: XOR salt back out */
    volatile uint32_t result = mixed ^ salt;
    return result;
}

/* Second address mixer using a different anchor */
static __attribute__((noinline)) uint32_t addr_mix2(uint32_t val)
{
    volatile uintptr_t fptr = (uintptr_t)(void *)ks_anchor2;
    volatile uint32_t salt = (uint32_t)(fptr >> 2);
    volatile uint32_t tmp = val + salt;
    volatile uint32_t result = tmp - salt;
    return result;
}

/* Stack-pointer mix: reads approximate SP, mixes, cancels */
static __attribute__((noinline)) uint32_t sp_mix(uint32_t val)
{
    volatile uint32_t dummy;
    volatile uintptr_t sp_approx = (uintptr_t)&dummy;
    volatile uint32_t sp32 = (uint32_t)(sp_approx & 0xFFFFFFFFU);
    volatile uint32_t tmp = val ^ sp32;
    volatile uint32_t result = tmp ^ sp32;
    return result;
}

/*
 * Core: ks_get(slot) returns the OBFK_A..H value for slot 0..7.
 *
 * Each slot uses a unique derivation path. The real constant is
 * built from sub-expressions; decoy branches emit fake values.
 */
__attribute__((noinline))
uint32_t ks_get(int slot)
{
    volatile int s = slot;
    volatile uint32_t r = 0;

    /* Dead branch 1: uses decoy_pool, never taken */
    if (!ks_opaque((uint32_t)s + 1)) {
        r = decoy_pool[s & 0xF] ^ 0x41414141U;
        return addr_mix(r);
    }

    /* Dead branch 2: another fake path */
    volatile uint32_t phantom = decoy_pool[(s * 7 + 3) & 0xF];
    if (!ks_opaque((uint32_t)s * 2 + 5)) {
        return sp_mix(phantom ^ 0xFFFFFFFFU);
    }

    switch (s) {
    case 0: {
        /* OBFK_A = 0x9E3779B9 */
        volatile uint32_t t1 = 0x9E370000U;
        volatile uint32_t t2 = 0x000079B9U;
        t1 = addr_mix(t1);
        t2 = sp_mix(t2);
        r = t1 | t2;
        /* Rotate right 13, then left 13 (identity) to add complexity */
        volatile uint32_t rr = (r >> 13) | (r << 19);
        r = (rr << 13) | (rr >> 19);
        r = addr_mix2(r);
        break;
    }
    case 1: {
        /* OBFK_B = 0x6C62272E */
        volatile uint32_t base = 0x6C000000U;
        volatile uint32_t mid  = 0x00622700U;
        volatile uint32_t low  = 0x0000002EU;
        base = addr_mix(base);
        mid  = sp_mix(mid);
        low  = addr_mix2(low);
        r = base | mid | low;
        /* Add then subtract a derived value */
        volatile uint32_t noise = ks_anchor(0x12345678U);
        r += noise;
        r -= noise;
        break;
    }
    case 2: {
        /* OBFK_C = 0x243F6A88 */
        volatile uint32_t hi = 0x243F0000U;
        volatile uint32_t lo = 0x00006A88U;
        hi = sp_mix(hi);
        lo = addr_mix(lo);
        r = hi | lo;
        /* Multiply by 1 via (x*3 - x*2) */
        volatile uint32_t r3 = r * 3;
        volatile uint32_t r2 = r * 2;
        r = r3 - r2;
        r = addr_mix2(r);
        break;
    }
    case 3: {
        /* OBFK_D = 0x85A308D3 */
        volatile uint32_t a = 0x85A30000U;
        volatile uint32_t b = 0x000008D3U;
        /* XOR with constant, then XOR back */
        a ^= 0xABCDEF01U;
        a = addr_mix(a);
        a ^= 0xABCDEF01U;
        b = sp_mix(b);
        r = a | b;
        break;
    }
    case 4: {
        /* OBFK_E = 0x13198A2E */
        volatile uint32_t p1 = 0x13190000U;
        volatile uint32_t p2 = 0x00008A2EU;
        p1 = addr_mix2(p1);
        p2 = addr_mix(p2);
        r = p1 | p2;
        /* NOT NOT identity */
        r = ~r;
        r = sp_mix(r);
        r = ~r;
        break;
    }
    case 5: {
        /* OBFK_F = 0x03707344 */
        volatile uint32_t x = 0x03700000U;
        volatile uint32_t y = 0x00007344U;
        x = sp_mix(x);
        y = addr_mix2(y);
        r = x | y;
        /* Rotate left 7 then right 7 */
        volatile uint32_t rl = (r << 7) | (r >> 25);
        r = (rl >> 7) | (rl << 25);
        r = addr_mix(r);
        break;
    }
    case 6: {
        /* OBFK_G = 0xA4093822 */
        volatile uint32_t w1 = 0xA4090000U;
        volatile uint32_t w2 = 0x00003822U;
        w1 = addr_mix(w1);
        w2 = sp_mix(w2);
        r = w1 + w2; /* OR equivalent since no bit overlap */
        /* Subtract then add back */
        volatile uint32_t sub = ks_anchor2(0x77777777U);
        r -= sub;
        r = addr_mix2(r);
        r += sub;
        break;
    }
    case 7: {
        /* OBFK_H = 0x299F31D0 */
        volatile uint32_t m1 = 0x299F0000U;
        volatile uint32_t m2 = 0x000031D0U;
        m1 = addr_mix2(m1);
        m2 = addr_mix(m2);
        r = m1 | m2;
        /* XOR with stack-derived salt, then cancel */
        volatile uint32_t sd;
        volatile uintptr_t spp = (uintptr_t)&sd;
        volatile uint32_t ss = (uint32_t)spp;
        r ^= ss;
        r = sp_mix(r);
        r ^= ss;
        break;
    }
    default:
        /* Return a decoy for invalid slots */
        r = decoy_pool[s & 0xF];
        break;
    }

    /* Final dead branch with decoy */
    if (!ks_opaque(r & 0xFF)) {
        return phantom ^ r;
    }

    return r;
}
