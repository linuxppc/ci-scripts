#!/bin/bash

set -euo pipefail

rm -rf libkcapi
tar -xf libkcapi.tar.gz
mv smuellerDD-libkcapi-* libkcapi

if [[ -n ${MAKEFLAGS:-} ]]; then
    # Don't override existing make flags
    jflags=
else
    jflags="-j $(nproc)"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    cd libkcapi

    set -x
    autoreconf -i
    ./configure --enable-kcapi-test --enable-kcapi-speed --enable-kcapi-hasher --enable-kcapi-rngapp --enable-kcapi-encapp --enable-kcapi-dgstapp
    make $jflags
    set +x

    cd test
    sed -i -e "s/ROUNDS=100/ROUNDS=10/" kcapi-fuzz-test.sh

    failed=0
    for test in test.sh kcapi-enc-test.sh hasher-test.sh kcapi-dgst-test.sh kcapi-enc-test-large.sh kcapi-fuzz-test.sh
    do
        echo "========================================"
        echo " Running $test ..."
        echo "========================================"
        rc=0
        ./$test || rc=1
        if [[ $rc -ne 0 ]]; then
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            echo " FAILED $test"
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            failed=$((failed+1))
        fi
    done

    if [[ $failed -ne 0 ]]; then
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo " FAILED $failed tests!"
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        exit 1
    fi

    set +x
    echo "success: libkcapi" >&2

} 2>&1 >> log | tee -a log
