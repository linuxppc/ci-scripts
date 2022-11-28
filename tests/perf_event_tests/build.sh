#!/bin/bash

set -euo pipefail

rm -rf perf_event_tests
tar -xf perf_event_tests.tar.gz
mv deater-perf_event_tests* perf_event_tests
touch perf_event_tests

if [[ -n ${MAKEFLAGS:-} ]]; then
    # Don't override existing make flags
    jflags=
else
    jflags="-j $(nproc)"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    cd perf_event_tests

    (set -x; make $jflags)

    echo "success: perf_event_tests" >&2

} 2>&1 >> log | tee -a log
