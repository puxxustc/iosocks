# iosocks  #

A lightweight SOCKS5 proxy

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

**isocks**

```bash
usage: isocks
  -h, --help        show this help
  -c <config_file>  config file, see iosocks(8) for its syntax
```

**osocks**

```bash
usage: osocks
  -h, --help        show this help
  -c <config_file>  config file, see iosocks(8) for its syntax
```

**iodns**

```bash
usage: iodns
  -h, --help        show this help
  -c <config_file>  config file, see iosocks(8) for its syntax
```

**ioredir**

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
