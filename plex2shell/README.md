# plex2shell

GPLv3 framework for exploiting Plex Media Server misconfigurations and gaining an interactive shell. See header in `plex2shell.py` for license text (Copyright 2026 code-zm).

## Files

| File | Description |
|------|-------------|
| `plex2shell.py` | Main exploit / shell driver |
| `payload_linux.c` | Linux payload source |
| `payload_windows.c` | Windows payload source |
| `payload_linux_plex2shell` | Prebuilt Linux payload binary |

## Usage

Make binaries executable and run the payload helper (lab only):

```bash
chmod +x payload_linux_plex2shell plex2shell.py
./payload_linux_plex2shell
```

For target discovery in authorized assessments, combine with your own scanning toolchain (e.g. zmap) against hosts you are permitted to test.

Run the Python framework directly:

```bash
python3 plex2shell.py --help
```

Refer to `plex2shell.py` argparse for server URL, callback, and mode options.

## Disclaimer

Authorized security research and owned/lab systems only. Do not use against third-party Plex instances without explicit permission.
