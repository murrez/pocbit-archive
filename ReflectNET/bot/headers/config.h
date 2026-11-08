#pragma once

/* Bot build version — increment on every fleet-visible release.
 * CNC uses this to decide which bots need OTA (Phase 4+). */
#ifndef BOT_VERSION
#define BOT_VERSION 3
#endif

/* Optional compile-time arch (-DBOT_ARCH=1 for BOT_ARCH_MIPS, etc.).
 * If unset, cnc_get_arch() uses uname() at runtime. */
