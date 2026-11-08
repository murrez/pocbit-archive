# massload

**meowloader** — single large Go binary aggregating dozens of router/IoT CVE exploit functions (Huawei HG532, Realtek SOAP, GPON, Zyxel, D-Link, Tenda, Netgear, telnet direct install, reverse shell push, etc.). Includes `pkg/hexify` helpers and optional C dropper source under `csource/`.

## Layout

```
massload/
├── meowloader.go       # Main (~8k+ lines)
├── go.mod
├── scan.sh / mass.sh   # Orchestration
├── csource/dlr.c       # Quantum/qtm dropper C source
└── pkg/hexify/         # Payload encoding helpers
```

## Build

```bash
go build -o meowloader meowloader.go
```

## Usage

Targets and mode depend on `main()` flags and stdin conventions—grep `func main` and subcommands in `meowloader.go`.

Common patterns in source:

- `selfContainedPayload` — arch-detect + wget/curl/tftp bot fetch without server-side `cats.sh`
- `telnetDirectScan` — unauthenticated telnet/busybox install
- Per-CVE functions in the `CVE-20xx` comment sections

## Configuration

- Set loader/C2 IP and binary names throughout `meowloader.go` (many hardcoded URLs).
- `logFolder/infected.txt` may contain sensitive scan logs—add to `.gitignore`.

## Disclaimer

Authorized red-team lab and owned hardware only. Not for internet-wide scanning.
