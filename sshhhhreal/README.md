# sshhhhreal

SSH port probe and **brute-force** helper package, intended to plug into the `scanner` Go module layout.

## Layout

```
sshhhhreal/
├── ssh.go              # Banner check → brute.BruteForce
├── brute/brute.go
├── login/login.go
├── login/password.go
├── login/command.go
├── honeypot/honeypot.go
├── honeypot/detection.go
└── utils/
```

## Import paths

Sources import `scanner/exploits/ssh/...`. This repo expects `sshhhhreal` to live beside or inside a `scanner` module tree. Options:

1. Move packages under `scanner/exploits/ssh/`, or  
2. Add a `go.mod` `replace` directive pointing to this folder.

## Usage

Wire `ssh.NewTarget(host)` from your scanner driver after TCP/22 discovery.

## Honeypot

`honeypot/` heuristics skip low-interaction SSH traps before brute.

## Disclaimer

Authorized credential audits only. Brute-forcing third-party SSH is illegal.
