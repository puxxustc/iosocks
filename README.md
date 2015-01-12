# iosocks #

[![Build Status](https://travis-ci.org/XiaoxiaoPu/iosocks.svg?branch=master)](https://travis-ci.org/XiaoxiaoPu/iosocks)

A lightweight tunnel proxy, provides a SOCKS5 proxy, a DNS forwarder and a transparent  TCP  proxy.

## Build ##

### install libev ###

```bash
# Archlinux
sudo pacman -S libev
# CentOS
sudo yum install libev-devel
# Debian/Ubuntu
sudo apt-get install libev-dev
```

### make & install ###

```bash
# if automake < 1.14, run `autoreconf -i'
./configure --prefix=/usr
make
sudo make install
```

## Usage ##

**osocks**

runs on a remote server to provide secured tunnel service.

```bash
usage: osocks
  -h, --help        show this help
  -c <config_file>  config file, see iosocks(8) for its syntax
```

**isocks**

A standard SOCKS5 proxy.

```bash
usage: isocks
  -h, --help        show this help
  -c <config_file>  config file, see iosocks(8) for its syntax
```

**iodns**

A DNS forwarder that transmits all DNS queries throw the tunnel.

```bash
usage: iodns
  -h, --help        show this help
  -c <config_file>  config file, see iosocks(8) for its syntax
```

**ioredir**

A transparent TCP proxy.

```bash
usage: ioredir
  -h, --help        show this help
  -c <config_file>  config file, see iosocks(8) for its syntax
```

**sample config file**

```ini
[server]
address=192.168.1.1
port=1205
key=testkey

[server]
address=192.168.1.2
port=1205
key=testkey2

[local]
address=127.0.0.1
port=1080

[dns]
address=127.0.0.1
port=5300
upstream_addr=8.8.8.8
upstream_port=53

[redir]
address=127.0.0.1
port=1081
iptables=true
```


## License ##

Copyright (C) 2014, Xiaoxiao <i@xiaoxiao.im>

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
