#!/bin/bash

set -euo pipefail

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

rm -rf audit-testsuite
tar -xf audit-testsuite.tar.gz
mv linux-audit-audit-testsuite* audit-testsuite

if [[ -n ${MAKEFLAGS:-} ]]; then
    # Don't override existing make flags
    jflags=
else
    jflags="-j $(nproc)"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    cd audit-testsuite
    make $jflags

    timeout 1h $sudo make $jflags test

    set +x
    echo "success: audit-testsuite" >&2

} 2>&1 >> log | tee -a log
