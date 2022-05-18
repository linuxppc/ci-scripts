#!/bin/bash

set -euo pipefail

rm -rf vdsotest
tar -xf vdsotest.tar.gz
mv nathanlynch-vdsotest* vdsotest

if [[ -n ${MAKEFLAGS:-} ]]; then
    # Don't override existing make flags
    jflags=
else
    jflags="-j $(nproc)"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    cd vdsotest

    ./autogen.sh
    ./configure
    make $jflags

    exception_trace=$(cat /proc/sys/debug/exception-trace)

    # Disable show_unhandled_signals
    if [[ -w /proc/sys/debug/exception-trace ]]; then
        echo 0 > /proc/sys/debug/exception-trace
    fi

    ./vdsotest list-apis
    for api in $(./vdsotest list-apis)
    do
        for testtype in $(./vdsotest list-test-types)
        do
            timeout 5m ./vdsotest "$api" "$testtype"
        done
    done

    if [[ -w /proc/sys/debug/exception-trace ]]; then
        echo "$exception_trace" > /proc/sys/debug/exception-trace
    fi

    set +x
    echo "success: vdsotest" >&2

} 2>&1 >> log | tee -a log
