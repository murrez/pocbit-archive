# P2P mesh agent (`guardian_p2p`)

Distributed overlay bot with DHT, gossip, and an operator control plane. Build with `make` (see `Makefile`); binary name in this tree: `guardian_p2p`.

## Quick start (two terminals)

### Terminal 1 — operator

Listen for peer connections (must show `tcp` listening on `0.0.0.0:6974`):

```bash
./guardian_p2p --operator --operator-key keys/admin.sec --port 6974 --allow-private --foreground
```

Standalone operator mode uses the same flags.

### Terminal 2 — peer bot

Connect to the operator:

```bash
./guardian_p2p --peer 127.0.0.1:6974 --allow-private --foreground
```

Replace `127.0.0.1` with the operator’s reachable address. Use `--allow-private` only in lab/VPN environments.

## Related paths

| Path | Role |
|------|------|
| `main/main.c` | Entry point |
| `core/dht/`, `core/gossip/`, `core/overlay/` | Networking and attack engine |
| `keys/admin.sec`, `keys/admin.pub` | Operator key material (**do not commit secrets**) |
| `tools/keygen` | Key generation helper |

## Notes

- `keys/admin.sec` is sensitive; rotate before any public repository push.
- Logs may appear as `p2p_agent.log` in the project root after runs.
