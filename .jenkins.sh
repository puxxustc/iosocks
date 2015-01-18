#!/usr/bin/env bash

set -e

if [ -f Makefile ]; then
	make distclean
fi
./configure --enable-debug
make
test/test.py

gcov src/*.c
cd src
gcovr -r . --html  --html-details  -o index.html
cd ..
COVERAGE=$(gcovr -r . | grep TOTAL | rev | cut -d' ' -f 1 | rev)
{
    cat <<EOF
<svg xmlns="http://www.w3.org/2000/svg" width="99" height="20"><linearGradient id="a" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><rect rx="3" width="99" height="20" fill="#555"/><rect rx="3" x="63" width="36" height="20" fill="#dfb317"/><path fill="#dfb317" d="M63 0h4v20h-4z"/><rect rx="3" width="99" height="20" fill="url(#a)"/><g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11"><text x="32.5" y="15" fill="#010101" fill-opacity=".3">coverage</text><text x="32.5" y="14">coverage</text><text x="80" y="15" fill="#010101" fill-opacity=".3">
EOF
	echo -n ${COVERAGE}
	cat <<EOF
</text><text x="80" y="14">
EOF
    echo -n ${COVERAGE}
    cat <<EOF
</text></g></svg>
EOF
} >coverage.svg
