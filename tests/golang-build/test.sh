#!/bin/bash

set -euo pipefail

name="golang-build"
echo "test: $name"

rc=0
go version || rc=1
if [[ $rc -ne 0 ]]; then
    echo "Error: go missing, install with package manager" >&2
    echo "failure: $name"
    exit 1
fi

rm -rf go-go1.16.6
tar -xf go1.16.6.tar.gz
cd go-go1.16.6/src

echo "Building ..."
./all.bash

../bin/go run ../test/helloworld.go

echo "success: $name"

exit 0
