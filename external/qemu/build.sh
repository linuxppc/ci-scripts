#!/bin/bash

set -euo pipefail

if [[ -n ${MAKEFLAGS:-} ]]; then
    # Don't override existing make flags
    jflags=
else
    jflags="-j $(nproc)"
fi

version=$1

echo "Sending output to $PWD/log."
rm -f log

{
    rm -rf qemu-$version
    mkdir -p qemu-$version
    cd qemu-$version
    tar -xf ../qemu-${version}.tar.xz
    if [[ "$version" == "mainline" ]]; then
	    mv qemu-qemu-* src
    else
	    mv qemu-$version src
    fi

    mkdir install
    install="$PWD/install"

    mkdir build
    cd build

    set -x

    ../src/configure --prefix=$install --target-list=ppc-softmmu,ppc64-softmmu --disable-gtk
    make $jflags -s
    make $jflags -s install
    cd ..

    rm -rf src build

    set +x
    echo "success: qemu $version build" >&2

} 2>&1 >> log | tee -a log
