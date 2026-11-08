# broadband-router

Single-file Go brute/exploit for **Comtrend**-class broadband routers. Tries built-in credential pairs over the device management interface.

## File

- `comtrend.go` — concurrent worker pool, stdin or file-driven targets

## Build & run

```bash
go build -o comtrend comtrend.go
./comtrend   # see main() for input format
```

Default combo list includes entries such as `root:12345`, `admin:admin`, `guest:guest` (see source).

## Configuration

Edit exploit payload strings and C2 URLs inside `comtrend.go` for your isolated lab.

## Disclaimer

Authorized security research only.
