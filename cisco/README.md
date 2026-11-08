# cisco

GoAhead-banner **Cisco RV** (and similar) session brute + remote command execution. Matches `Server: GoAhead-Webs` and tries credential combos from source.

## File

- `main.go`

## Configuration

| Constant | Purpose |
|----------|---------|
| `Payload` | Remote fetch command — set `urip` to your lab host |
| `Combos` | `user:pass` list |
| `HttpBanner` | Target fingerprint |

## Build & run

```bash
go build -o cisco main.go
# targets on stdin (one host per line) — see main()
```

## TLS

Uses permissive TLS (`InsecureSkipVerify`) for HTTPS management ports.

## Disclaimer

Authorized testing on lab gear only.
