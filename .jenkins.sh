#!/usr/bin/env bash

set -e

if [ -f Makefile ]; then
	make distclean
fi
rm -f *.gcov src/*.gcda src/*.gcno  src/*.html

./configure --enable-debug
make

sudo iptables -t nat -N iosocks
sudo iptables -t nat -A iosocks -d 0.0.0.0/8 -j RETURN
sudo iptables -t nat -A iosocks -d 10.0.0.0/8 -j RETURN
sudo iptables -t nat -A iosocks -d 127.0.0.0/8 -j RETURN
sudo iptables -t nat -A iosocks -d 169.254.0.0/16 -j RETURN
sudo iptables -t nat -A iosocks -d 172.16.0.0/12 -j RETURN
sudo iptables -t nat -A iosocks -d 192.168.0.0/16 -j RETURN
sudo iptables -t nat -A iosocks -d 224.0.0.0/4 -j RETURN
sudo iptables -t nat -A iosocks -d 240.0.0.0/4 -j RETURN
sudo iptables -t nat -A iosocks -p tcp -j REDIRECT --to-ports 1081
sudo iptables -t nat -A OUTPUT -p tcp --sport 2000 -j iosocks
sudo iptables -t nat -A OUTPUT -p tcp --sport 2001 -j iosocks
sudo iptables -t nat -A OUTPUT -p tcp --sport 2002 -j iosocks
sudo iptables -t nat -A OUTPUT -p tcp --sport 2003 -j iosocks

test/test.py

sudo iptables -t nat -D OUTPUT -p tcp --sport 2000 -j iosocks
sudo iptables -t nat -D OUTPUT -p tcp --sport 2001 -j iosocks
sudo iptables -t nat -D OUTPUT -p tcp --sport 2002 -j iosocks
sudo iptables -t nat -D OUTPUT -p tcp --sport 2003 -j iosocks
sudo iptables -t nat -F iosocks
sudo iptables -t nat -X iosocks

gcov src/*.c
cd src
gcovr -r . --html  --html-details  -o index.html
cd ..
COVERAGE=$(gcovr -r . | grep TOTAL | awk '{print $4}')
{
	cat <<EOF
<svg xmlns="http://www.w3.org/2000/svg" width="99" height="20"><linearGradient id="a" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><rect rx="3" width="99" height="20" fill="#555"/><rect rx="3" x="63" width="36" height="20" fill="#dfb317"/><path fill="#dfb317" d="M63 0h4v20h-4z"/><rect rx="3" width="99" height="20" fill="url(#a)"/><g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11"><text x="32.5" y="15" fill="#010101" fill-opacity=".3">coverage</text><text x="32.5" y="14">coverage</text><text x="80" y="15" fill="#010101" fill-opacity=".3">100%</text><text x="80" y="14">100%</text></g></svg>
EOF
} | sed "s/100%/${COVERAGE}/g" >iosocks-coverage.svg
