# tenda_telnet

Enables **root telnetd** on vulnerable **Tenda** routers via unauthenticated `POST /goform/telnet` (AC10 `httpd` reference symbol `0x45b7f0`). Default shipped creds on tested firmware: `user:1234`, `support:1234`.

## File

- `main.go`

## Build

```bash
GO111MODULE=off go build -o tenda_telnet main.go
```

## Limits (from source comments)

- Telnet often binds **LAN** only; WAN:23 may still be firewalled on tested units.
- Verified on multiple live units returning `load telnetd success.` in lab reporting.

## Usage

Feed host list per `main()` (stdin/flags).

## Disclaimer

**AUTHORIZED TESTING ONLY** (stated in source). Owned router hardware or explicit vendor permission.
