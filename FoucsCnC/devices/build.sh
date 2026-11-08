#!/bin/sh
# language: Shell, file: build.sh, target: Multi-arch Build Script
set -e

LDFLAGS="-s -w"
SRC="bot.go"

build() {
    echo "Building for $1/$2..."
    GOOS=$1 GOARCH=$2 GOARM=$3 go build -ldflags="$LDFLAGS" -o "bin/bot_$4" "$SRC"
    echo "Built bin/bot_$4"
}

mkdir -p bin
build linux 386    "" x86
build linux arm    7  armv7l
build linux arm    5  armv5l
build linux arm64  "" armv8l
build linux mips   "" mips
build linux mipsle "" mipsel

echo "All builds completed successfully."