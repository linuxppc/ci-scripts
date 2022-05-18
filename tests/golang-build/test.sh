#!/bin/bash

set -euo pipefail

rc=0
go version || rc=1
if [[ $rc -ne 0 ]]; then
    echo "Error: go missing, install with package manager" >&2
    exit 1
fi

echo "Sending output to $PWD/log."
rm -f log

rm -rf go-go1.16.6
tar -xf go1.16.6.tar.gz

{
	cd go-go1.16.6/src
	set -x
	./all.bash
	../bin/go run ../test/helloworld.go

	set +x
	echo "success: golang-build" >&2

} 2>&1 >> log | tee -a log
