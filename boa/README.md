# boa

Mass exploitation toolkit for **Boa** and related small embedded web servers on routers. Includes HTTP auth brute lists, ROM-style payloads, and optional `scanlisten.go` callback server.

## Files

| File | Description |
|------|-------------|
| `boa.go` | Main exploit / scanner |
| `scanlisten.go` | Infection callback listener |
| `scan.sh` | Scan orchestration script |

## Usage

```bash
go build -o boa boa.go
# feed IP list via file or stdin per main() implementation
```

## Configuration

**Required before use or GitHub push:**

- Replace hardcoded **NC/wget IPs** in `ftp_payload`, `wget_payload`, and related strings (currently contain third-party hosts).
- Credential lists: `boa_auths`, `xboa_auths`, `fboa_auths` — extend for your lab devices only.

## Related

Similar pipeline to `goahead/` and `router/` (embedded HTTP on ports 80/81).

## Disclaimer

Authorized testing only.
