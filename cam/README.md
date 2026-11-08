# cam

High-concurrency HTTP fingerprint and weak-credential probe for **Hikvision**, **Dahua**, **AXIS**, and **GoAhead**-style cameras. Successful hits append to `hits.txt`.

## File

- `cam.go` — 600 workers default, 8s task timeout

## Fingerprints

| Vendor | Path | Marker |
|--------|------|--------|
| Hikvision | `/ISAPI/System/deviceInfo` | `<model>` |
| Dahua | `/cgi-bin/configManager.cgi?...` | `table.General` |
| Axis | `/axis-cgi/admin/param.cgi?action=list` | `root.Brand.Brand=AXIS` |
| GoAhead | `/system.ini` | `http_password` |

## Usage

```bash
go build -o cam cam.go
cat targets.txt | ./cam
```

See `tut.txt` for operational notes.

## Output

- Counter stats on stderr
- `hits.txt` for positive matches

## Disclaimer

Owned cameras and written permission only.
