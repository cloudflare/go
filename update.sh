#!/usr/bin/env bash

set -e
if [ ! -d fast-export ]; then
	echo 'update.sh must be run from the repo root' 1>&2
	exit 1
fi

if [ ! -d orig_repo ]; then
	hg clone https://code.google.com/p/go orig_repo
	pushd .
	cd orig_repo
	hg up null
	popd
fi

pushd .
cd orig_repo
hg pull
popd

./fast-export/hg-fast-export.sh -r orig_repo -o upstream