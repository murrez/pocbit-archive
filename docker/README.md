# Docker API — unauthenticated RCE (exposed daemon :2375/:2376)

Verified working: **~150+ "docker" bots registered on the milk CNC** from real hosts.

Fingerprint (Shodan): `port:2375 docker`, `port:2376 docker`, `product:"Docker"`.

Run: `python3 exploit.py targets.txt`
