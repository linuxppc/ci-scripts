#!/bin/bash

set -euo pipefail

rm -rf src
tar -xf ltp.tar.xz
mv ltp-full-* src

if [[ -n ${MAKEFLAGS:-} ]]; then
    # Don't override existing make flags
    jflags=
else
    jflags="-j $(nproc)"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    cd src

    set -x
    ./configure --prefix=$PWD/../install
    make $jflags -s
    make $jflags -s install
    rm -rf src

    set +x
    echo "success: ltp" >&2

} 2>&1 >> log | tee -a log
