# iosocks  #

A lightweight SOCKS5 proxy server

## Build ##

### install libev ###

```bash
# Archlinux
sudo pacman -S libev
# CentOS
sudo yum install libev-devel
```

### make ###

```bash
cd iosocks
make
```

## Usage ##

**Client**

```bash
usage: isocks
  -h, --help        show this help
  -s <server_addr>  server address
  -p <server_port>  server port, default: 8388
  -b <local_addr>   local binding address, default: 127.0.0.1
  -l <local_port>   local port, default: 1080
  -k <key>          encryption key
```

**Server**

```bash
usage: osocks
  -h, --help          show this help
  -s <server_addr>    server address, default: 0.0.0.0
  -p <server_port>    server port, default: 8388
  -k <key>            encryption key
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
