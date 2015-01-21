#!/usr/bin/env bash

set -e

STATUS=$(curl -s https://scan.coverity.com/projects/3948/badge.svg)

if [[ $(echo ${STATUS} | grep defects) ]]; then
	DEFECTS=$(echo ${STATUS} | sed 's/passed/\n/g' | grep defects | sed -n '1p' | awk '{print $1}')
	curl -s -o .coverity.svg "https://img.shields.io/badge/coverity-passed%20${DEFECTS}%20defects-yellow.svg?style=flat"
elif [[ $(echo ${STATUS} | grep passed) ]]; then
	curl -s -o .coverity.svg 'https://img.shields.io/badge/coverity-passed-brightgreen.svg?style=flat'
elif [[ $(echo ${STATUS} | grep pending) ]]; then
	curl -s -o .coverity.svg 'https://img.shields.io/badge/coverity-pending-yellow.svg?style=flat'
elif [[ $(echo ${STATUS} | grep failed) ]]; then
	curl -s -o .coverity.svg 'https://img.shields.io/badge/coverity-failed-red.svg?style=flat'
fi
