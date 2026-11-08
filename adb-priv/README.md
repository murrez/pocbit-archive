# adb-priv

ADB-based mass command injection over **SOCKS4 proxies**, plus an optional Android carrier app (`reaverbotApp`) for persistence and native payload delivery.

> **Authorized testing only.** Do not scan or command devices you do not own.

## Components

| Path | Description |
|------|-------------|
| `loader/adb.go` | Main tool: ADB wire protocol, threaded workers, optional proxy rotation |
| `loader/payloads.txt` | Shell command templates |
| `loader/proxies.txt` | SOCKS4 proxy list |
| `reaverbotApp/` | Gradle Android project (`BootReceiver`, `IranbotService`, `assets/libkys.so`) |

## Loader usage

```bash
cd loader
go build -o adb-loader adb.go
./adb-loader <ip> <port> [options]
```

| Flag | Purpose |
|------|---------|
| `-j` / `--threads` | Worker count |
| `-d` / `--debug` | Debug logging |
| `-f` / `--debug-full` | Lenient protocol parsing |
| `-o` / `--output` | Show command output |
| `-r` / `--restart` | Restart workers every N seconds |

Requires `go.mod` dependencies: `github.com/bdandy/go-socks4`, `golang.org/x/net/proxy`.

## Android app

```bash
cd reaverbotApp
./gradlew assembleDebug
```

Output APK under `app/build/outputs/apk/debug/`. **Do not commit** `.gradle/`, `gradle_user_home/`, or build intermediates to GitHub.

## Configuration

- Edit `payloads.txt` for lab-only commands.
- Replace hardcoded callback URLs/IPs in source before publishing.

## Disclaimer

Research and owned devices only. Open ADB on the public internet is a misconfiguration—use findings to improve defenses.
