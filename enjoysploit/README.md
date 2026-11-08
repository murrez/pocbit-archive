# enjoysploit

Small **CVE proof-of-concept** collection (Go and Python). Each subdirectory is standalone.

> Replace all CNC/payload URLs and build tags before lab use. **Authorized targets only.**

## Modules

| Path | CVE / target | Language |
|------|----------------|----------|
| [gitea/](gitea/) | CVE-2026-60004 Gitea ≤1.27 pre-auth RCE | Go |
| [xwiki/](xwiki/) | CVE-2025-24893 XWiki SolrSearch Groovy RCE | Go |
| [vcenter/](vcenter/) | VMware vCenter syslog RCE class | Python |
| [activemq_openwire/](activemq_openwire/) | ActiveMQ OpenWire deserialization | Python + `poc.xml` |

## Build examples

```bash
cd gitea && go build -o gitea main.go
cd xwiki && GO111MODULE=off go build -o xwiki main.go
cd vcenter && python3 exploit.py --help
cd activemq_openwire && python3 exploit.py
```

## gitea

Hook/patch-based RCE; default bot tag `gitea` in source—change to your test binary.

## xwiki

```bash
./xwiki -url http://host:8080
```

## activemq_openwire

Spring/XML bean chain; reference payload in `poc.xml`.

## Disclaimer

Security research and vendor-coordinated disclosure only. Do not weaponize against production without permission.
