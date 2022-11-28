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
    rm -rf src
    tar -xf qemu.tar.xz
    mv qemu-* src

    rm -rf install
    mkdir install
    install="$PWD/install"

    rm -rf build
    mkdir build
    cd build

    set -x

    ../src/configure --prefix=$install --target-list=ppc-softmmu,ppc64-softmmu --disable-gtk
    make $jflags -s
    make $jflags -s install
    cd ..

    rm -rf src build

    set +x
    echo "success: qemu build" >&2

} 2>&1 >> log | tee -a log
