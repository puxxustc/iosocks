#!/usr/bin/env bash

set -e

LIBEV=4.19

# Download libev
if ! [ -f "libev-${LIBEV}.tar.gz" ]; then
	curl -o "libev-${LIBEV}.tar.gz" \
	    "http://dist.schmorp.de/libev/libev-${LIBEV}.tar.gz"
fi

# Build libev
tar -xf "libev-${LIBEV}.tar.gz"
mv "libev-${LIBEV}" libev
cd libev
./configure $@
if [ -f Makefile ]; then
	make
fi
cd ..
sed -i 's/$(LIB_EV)//g' src/Makefile.am
autoreconf -if
_CFLAGS="${CFLAGS}"
_LIBS="${LIBS}"
export CFLAGS="${CFLAGS} -I $(pwd)/libev"
export LIBS="${LIBS} $(pwd)/libev/.libs/libev.a -lm"
./configure $@
if [ -f Makefile ]; then
	make
fi
CFLAGS="${_CFLAGS}"
LIBS="${_LIBS}"
rm -rf libev
git checkout HEAD src/Makefile.am
