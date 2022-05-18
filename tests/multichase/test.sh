#!/bin/bash

set -euo pipefail

rm -rf multichase
tar -xf multichase.tar.gz
mv google-multichase* multichase

if [[ -n ${MAKEFLAGS:-} ]]; then
    # Don't override existing make flags
    jflags=
else
    jflags="-j $(nproc)"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    cd multichase

    set -x
    make $jflags
    ./multichase
    ./multiload
    ./pingpong -u
    ./fairness

    set +x
    echo "success: multichase" >&2

} 2>&1 >> log | tee -a log
