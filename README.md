# iosocks #

[![Release](https://img.shields.io/github/release/XiaoxiaoPu/iosocks.svg?style=flat)](https://github.com/XiaoxiaoPu/iosocks/releases/latest)
[![License](https://img.shields.io/badge/license-GPL%203-blue.svg?style=flat)](http://www.gnu.org/licenses/gpl.html)
[![Build Status](https://travis-ci.org/XiaoxiaoPu/iosocks.svg?branch=master)](https://travis-ci.org/XiaoxiaoPu/iosocks)
[![Build Status](https://jenkins.xiaoxiao.im/buildStatus/icon?job=iosocks)](https://jenkins.xiaoxiao.im/job/iosocks/)

A lightweight tunnel proxy, provides a SOCKS5 proxy and a transparent TCP proxy.

## Build ##

1. install libev (optional)

	```bash
	# Archlinux
	sudo pacman -S libev
	# CentOS
	sudo yum install libev-devel
	# Debian/Ubuntu
	sudo apt-get install libev-dev
	```

2. configure and make

	```bash
	autoreconf -if
	./configure --prefix=/usr --sysconfdir=/etc
	make
	```

3. install

	```bash
	sudo make install
	```

## Cross compile ##

1. setup cross compile tool chain

2. build

	```bash
	autoreconf -if
	./configure --host=arm-unknown-linux-gnueabihf \
	    --prefix=/usr --sysconfdir=/etc
	```

## Usage ##

See man:iosocks(8).

## Advanced usage ##

ioredir prorides a transpant TCP proxy. This feature requires Linux netfilter's NAT function.

```bash
iptables -t nat -N iosocks
iptables -t nat -A iosocks -d ${server} -j RETURN
iptables -t nat -A iosocks -d 0.0.0.0/8 -j RETURN
iptables -t nat -A iosocks -d 10.0.0.0/8 -j RETURN
iptables -t nat -A iosocks -d 127.0.0.0/8 -j RETURN
iptables -t nat -A iosocks -d 169.254.0.0/16 -j RETURN
iptables -t nat -A iosocks -d 172.16.0.0/12 -j RETURN
iptables -t nat -A iosocks -d 192.168.0.0/16 -j RETURN
iptables -t nat -A iosocks -d 224.0.0.0/4 -j RETURN
iptables -t nat -A iosocks -d 240.0.0.0/4 -j RETURN
iptables -t nat -A iosocks -p tcp -j REDIRECT --to-ports 1081
iptables -t nat -A OUTPUT -p tcp -j iosocks
iptables -t nat -A PREROUTING -p tcp -j iosocks
```

## License ##

Copyright (C) 2014 - 2015, Xiaoxiao <i@xiaoxiao.im>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
