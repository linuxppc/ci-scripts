#!/bin/bash

set -euo pipefail

rm -rf will-it-scale
tar -xf will-it-scale.tar.gz
mv antonblanchard-will-it-scale* will-it-scale

if [[ -n ${MAKEFLAGS:-} ]]; then
    # Don't override existing make flags
    jflags=
else
    jflags="-j $(nproc)"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    cd will-it-scale

    set -x
    make $jflags

    set +x
    echo "success: will-it-scale" >&2

} 2>&1 >> log | tee -a log
