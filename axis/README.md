# axis — CVE-2018-10660

Unauthenticated command injection on **AXIS** network cameras via `parhand`. Concurrent Go scanner; reads targets from **stdin** (e.g. zmap).

## CVE

**CVE-2018-10660** — AXIS camera `parhand` parameter injection.

## Usage

```bash
go build -o axis axis.go
zmap -p 80 -o- | ./axis
# or port 443 with TLS where applicable
```

## Flags

Use `-h` / source `flag` package for `debug` and concurrency options.

## Configuration

- **`loadURL` / `cmdQ3`:** Replace `stun.google.com` (and embedded wget URLs) with **your** lab payload server before running or publishing.
- Bot tag in payload string: `axis` (see `cmdQ3` constant).

## Fingerprint

`GET /axis-cgi/admin/systemlog.cgi` — body contains `<TITLE>AXIS` and `Network Camera`.

## Disclaimer

Authorized assessments and owned hardware only.
