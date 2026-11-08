# lll

**Mirai-derived** Linux botnet: C bot with vendor-specific scanners (Realtek, ThinkPHP, Huawei, HNAP), Go MySQL CNC, telnet `loader/src` binary server, and Python staging utilities.

## Layout

```
lll/
├── bot/           # C agent — scanner.c, attack_*.c, killer.c, vendor modules
├── cnc/           # Go — admin.go, database.go, attack.go, api.go, captcha
├── loader/src/    # Telnet dropper listener (cross-compiled stubs)
├── DEV/           # CNC banner/API Python helpers
├── payload.py     # HTTP binary staging
└── scanListen.go  # Infect callback TCP server
```

## Quick build

**Bot:** cross-compile per-arch Makefiles in `bot/` (see `build.sh` if present).

**CNC:**

```bash
cd cnc
go build
```

**Loader:** build `loader/src` with included cross compiler paths.

**Callbacks:**

```bash
go run scanListen.go
```

## Scanner modules (bot)

| Module | Target |
|--------|--------|
| `realtek.c` | Realtek SDK |
| `thinkphp.c` | ThinkPHP RCE probe |
| `huawei.c` | Huawei routers |
| `hnap_scanner.c` | HNAP |

## Disclaimer

Leaked/research material. Use only in closed lab networks.
