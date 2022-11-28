#!/bin/bash

set -euo pipefail

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    cd install

    set -x
    $sudo ./runltp $@

    set +x

    # Make sure logs aren't owned by root
    $sudo chown -R $(id -u) output

    echo "success: ltp" >&2

} 2>&1 >> log | tee -a log
