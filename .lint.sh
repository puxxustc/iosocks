#!/usr/bin/env bash

set -e

if [ -f Makefile ]; then
	make distclean
fi

export CC=/usr/lib/clang-analyzer/scan-build/ccc-analyzer
./configure
rm -rf .lint
scan-build -o .lint -analyze-headers --use-cc=clang make
cd .lint
DIR=$(ls)
mv ${DIR}/* ./
rmdir ${DIR}
cd ..

BUG=$(cat .lint/index.html | grep 'All Bugs' | tr '><' '\n' | grep '[0-9]')
if [ ${BUG} -lt 3 ]; then
	COLOR=brightgreen
elif [ ${BUG} -lt 6 ]; then
	COLOR=yellow
else
	COLOR=red
fi
if [ ${BUG} -eq 1 ]; then
	BUG="${BUG}%20bug"
else
	BUG="${BUG}%20bugs"
fi
curl -s -o .lint.svg "https://img.shields.io/badge/lint-${BUG}-${COLOR}.svg?style=flat"
