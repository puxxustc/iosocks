#!/usr/bin/env bash

set -e

export CC=gcc
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

cd src
rm -f *.html
gcov *.c
gcovr -r . --html  --html-details  -o index.html
cd ..

COVERAGE=$(gcovr -r . | grep TOTAL | awk '{print $4}' | cut -c 1-2)
if [ ${COVERAGE} -lt 60 ]; then
	URL="https://img.shields.io/badge/coverage-${COVERAGE}%-red.svg?style=flat"
elif [ ${COVERAGE} -lt 80 ]; then
	URL="https://img.shields.io/badge/coverage-${COVERAGE}%-yellow.svg?style=flat"
else
	URL="https://img.shields.io/badge/coverage-${COVERAGE}%-green.svg?style=flat"
fi
curl -s -o .coverage.svg ${URL}

make distclean
rm -f src/*.gcov src/*.gcda src/*.gcno
