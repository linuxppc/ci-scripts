#!/bin/bash

set -euo pipefail

rm -rf xfstests
tar -xf xfstests.tar.gz
mv master xfstests

if [[ -n ${MAKEFLAGS:-} ]]; then
    # Don't override existing make flags
    jflags=
else
    jflags="-j $(nproc)"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    cd xfstests

    set -x
    make $jflags

    set +x
    echo "xfstests built, run tests manually." >&2
    echo "success: xfstest" >&2

} 2>&1 >> log | tee -a log
