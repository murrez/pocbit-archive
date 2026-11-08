# etcd

Scans hosts with **etcd** API exposed (default **2379**), dumps keys/values, supports proxy rotation from `proxies.txt`, and writes loot to a configurable output directory.

## Files

| File | Role |
|------|------|
| `main.go` | Scanner/worker pool |
| `proxies.txt` | Optional HTTP/SOCKS-style proxy list |

## Usage

```bash
go build -o etcd-scanner main.go
./etcd-scanner -h    # flags: workers, timeout, port, output dir
```

Features (see source): stats counters, debug log, graceful shutdown, regex-based secret highlighting.

## Defensive note

Never expose etcd without TLS and auth to the internet. This tool demonstrates why.

## Disclaimer

Audit only systems you are authorized to assess.
