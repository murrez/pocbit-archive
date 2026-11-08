# rsync

Finds **open rsync** modules, lists paths, downloads interesting files, and optionally harvests SSH private keys into a loot directory. Supports proxy file and high worker concurrency.

## File

- `main.go`

## Filesystem inputs

| File | Purpose |
|------|---------|
| `proxies.txt` | Optional proxy rotation (if used by flags) |
| Output dir | Configurable loot folder for dumps |

## Usage

```bash
go build -o rsync-scanner main.go
./rsync-scanner -h
```

Flags include target port, workers, timeout, SSH key output path, and debug log (see `cfg*` variables at top of `main.go`).

## Defensive IOC

Unexpected `rsync` on TCP **873** from untrusted networks; anonymous module listings.

## Disclaimer

Authorized audits only.
