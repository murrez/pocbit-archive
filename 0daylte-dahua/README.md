# 0daylte-dahua

Go mass loader for **Dahua** devices using the proprietary binary protocol on **TCP 3001**. This is a port of the Python modules `lib/des.py`, `lib/crypt.py`, and `lib/binproto.py` into a single `load.go`.

> **Warning:** For **authorized security research**, forensics, and defensive engineering only. Unauthorized use against third-party systems is illegal in most jurisdictions. The bundled `ips.txt` is a sample target list—do not test against live hosts you do not own.

## Overview

| Item | Value |
|------|--------|
| Language | Go 1.x (`package main`, single file) |
| Ports | **3001** (Dahua service), then **23** (Telnet) |
| Input | `ips.txt` (one IP/hostname per line) |
| Concurrency | Default **200** goroutines; override with `./load [workers]` |
| Extra files | `passwd.txt` (upload payload), remote `0day.sh` (`urIP` placeholder in code) |

## Layout

```
0daylte-dahua/
├── load.go      # Loader — protocol, credential recovery, telnet, file transfer
├── ips.txt      # Target list (sample / scan output)
├── tut.txt      # Discovery pipeline notes (zmap, zgrab, filtering)
├── zgrab        # HTTP banner helper (binary/script; environment-specific)
└── README.md    # This file
```

## `load.go` architecture

### Cryptography

- **DES:** Bit reversal, custom padding, Base64 (`desEncode` / `desDecode`) for Dahua session fields.
- **tdDecrypt:** `gword` table and custom alphabet (`pat`) for password-recovery codes (`getPswCode`).
- **LOGON:** `Admin`/`Admin` probe yields `cryptKey` from `LOGONFAILED`; user/password hashed with MD5 + Base64 (`LoginWithKey`).

### Binary channel (`Channel`)

- Magic bytes: `f1 f5 ea f5` (commands), `f1 f5 ea f9` (data).
- Tab-separated message fields; `SendMsg` / `RecvMsg` queue.
- **`FILETRANSPORT`:** Streams `passwd.txt` in chunks via `SendData` to `/etc/passwd` on the device.

### Per-host workflow (`runHost`)

1. Quick **3001** reachability check (`portOpen`).
2. **`recover_`:** `FINDPSW` / `SECURITYCODE` / optional `RESERVEPHONE`; fallback `Default`/`Default` and `GETUSERINFO`.
3. **`enableTelnet`:** Authenticated `PARASET` / `COMMONENABLE` / `73748` variants; verify **23** is open.
4. **`setPasswd`:** Wait for `CMDID`, keep-alive goroutines, upload `passwd.txt`.
5. **`runCmd`:** Telnet login and remote `wget`/`tftp` shell script (replace **`urIP`** in code).
6. On success, **Discord webhook** (`sendWebhook`)—remove or externalize before any public fork.

Progress is logged on `stderr` with `[ip]` prefixes and a `[done/total]` counter.

## Configuration

| File / constant | Description |
|-----------------|-------------|
| `ips.txt` | Targets to process (blank lines skipped) |
| `passwd.txt` | Content written to the device—**not in repo**; you must supply it |
| `urIP` | Host in `runCmd` `wget`/`tftp` URLs—use only infrastructure you control |
| `webhookURL` | Hardcoded in `load.go`; delete or make configurable before publishing |
| Telnet creds | Hardcoded in `runCmd` (`root` / `cheems69`)—adjust for your lab images |

## Build and run

```bash
cd 0daylte-dahua
# Prepare passwd.txt
go build -o load load.go
./load          # default 200 workers
./load 400      # custom worker count
```

Or:

```bash
go run load.go [workers]
```

High concurrency on Linux:

```bash
ulimit -n 999999
ulimit -u 999999
```

## Discovery pipeline (`tut.txt` summary)

Operational notes live in `tut.txt`. Typical flow:

1. Regional IP zone files (e.g. ipdeny `.zone` lists).
2. **zmap** on port **3001** → `ips.txt`.
3. Optional **zgrab** HTTP banners → `ips.json`.
4. Filter records whose banner contains `dahua` → new `ips.txt`.
5. Run the `load` binary.

Use only in **your lab** or on assets with **written permission**.

## Defensive IOCs

- Unexpected inbound **3001** traffic and frequent `LOGON` / `FINDPSW` / `FILETRANSPORT` patterns.
- Sudden **Telnet (23)** exposure; `PARASET` / `COMMONENABLE` changes.
- `/etc/passwd`-style uploads over the proprietary protocol.
- Telnet sessions pulling `/tmp/0day.sh` via `wget`/`tftp`.
- Mitigations: strong passwords, current firmware, no internet-exposed management.

## Provenance

Third-party “0daylte” chain; this tree holds the Go port and helpers only. See `tut.txt` for scan notes.

## Suggested fork improvements

- Flags or `.env` for `webhookURL`, `urIP`, and Telnet credentials.
- Add `go.mod` and pin Go version.
- `.gitignore` `ips.txt` to avoid leaking real addresses.
