# geoscanner

**CVE-2024-36401** — GeoServer WFS `GetPropertyValue` blind RCE checker. Go port of an x86 Python scanner; confirms exploitability with time-based differential checks, then drops arch-matched payload from a configurable HTTP server.

## File

- `geoserver.go`

## Usage

```bash
go build -o geoserver geoserver.go
# URLs or host:port on stdin
cat targets.txt | ./geoserver
```

## Configuration

Change the hardcoded payload host (`IP:9111` / `urIP` comments in source) to your lab file server.

## Pipeline

1. Strict GeoServer fingerprint (WFS schema markers).
2. Blind timing exploit.
3. Infection wget one-liner with bot tag.

## Disclaimer

Patch GeoServer to a fixed release; use this only in authorized assessments.
