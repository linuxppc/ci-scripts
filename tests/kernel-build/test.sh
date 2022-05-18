#!/bin/bash

set -euo pipefail

if [[ -n ${MAKEFLAGS:-} ]]; then
    # Don't override existing make flags
    jflags=
else
    jflags="-j $(nproc)"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    set -x
    rm -rf linux
    tar -xf linux.tar.xz
    mv linux-* linux

    cd linux
    make $jflags defconfig
    make $jflags -s
    rm -rf linux

    set +x
    echo "success: kernel-build" >&2

} 2>&1 >> log | tee -a log
