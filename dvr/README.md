# dvr

**DVR/NVR/IP-camera** mass loader: reads hosts from **stdin**, optional custom port argument, chains multiple known CVE-style checks documented in the file header.

## Usage

```bash
go run main.go 56575          # default port in examples
zmap -p 56575 192.168.0.0/16 | go run main.go 56575
cat live.txt | ./main 56575
```

## CVE reference (from source comments)

Includes paths for Hikvision, Dahua, TVT, TBK, AVTECH, NUUO, QNAP, Realtek miniigd, and related issues on ports 80/443/8080/37777/52869, etc.

Port **56575** is used as a scan target in HiatusRAT-style campaigns (see comment block in `main.go`).

## File

- `main.go` — orchestration only; edit embedded payloads for your lab C2.

## Disclaimer

Forensics and authorized assessments only. Do not scan the public internet without legal clearance.
