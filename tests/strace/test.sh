#!/bin/bash

set -euo pipefail

rm -rf strace
tar -xf strace.tar.xz
mv strace-* strace

if [[ -n ${MAKEFLAGS:-} ]]; then
    # Don't override existing make flags
    jflags=
else
    jflags="-j $(nproc)"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    cd strace

    set -x
    ./configure
    make $jflags -s
    make $jflags -s check

    set +x
    echo "success: strace" >&2

} 2>&1 >> log | tee -a log

grep -B 1 -A 9 "Testsuite summary" log || true
