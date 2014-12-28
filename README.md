# iosocks  #

A lightweight SOCKS5 proxy server

## Build ##

```bash
# install libev first
cd iosocks
make
```

## Usage ##

**Client**

```bash
usage: isocks
  -h, --help          show this help
  -s <server_host>    host name or ip address of your remote server
  -p <server_port>    port number of your remote server
  -b <local_address>  local address to bind (default 127.0.0.1)
  -l <local_port>     port number of your local server (default 1080)
  -k <key>            encryption key
```

**Server**

```bash
usage: osocks
  -h, --help          show this help
  -a <server_host>    host name or ip address of your remote server
  -p <server_port>    port number of your remote server
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
