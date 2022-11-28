#!/bin/bash

set -euo pipefail

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    cd perf_event_tests

    if [[ "${1-}" == "api-test" ]]; then
        (set -x; $sudo ./run_tests.sh)
    fi

    if [[ -n "${2-}" ]]; then
        cd fuzzer
        (set -x; timeout --foreground "$2" $sudo ./perf_fuzzer)
        cd -
    fi

    echo "success: perf_event_tests" >&2

} 2>&1 >> log | tee -a log
