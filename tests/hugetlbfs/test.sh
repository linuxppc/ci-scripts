#!/bin/bash

set -euo pipefail

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

rm -rf libhugetlbfs
tar -xf libhugetlbfs.tar.gz
mv libhugetlbfs-* libhugetlbfs

if [[ -n ${MAKEFLAGS:-} ]]; then
    # Don't override existing make flags
    jflags=
else
    jflags="-j $(nproc)"
fi

echo "Sending output to $PWD/log."
rm -f log

{
    cd libhugetlbfs

    set -x
    make $jflags
    make $jflags -C tests all

    $sudo ./obj/hugeadm --create-global-mounts

    if [[ -d "/sys/kernel/mm/hugepages/hugepages-2048kB" ]]; then
        $sudo ./obj/hugeadm --pool-pages-min 2M:8192
    else
        $sudo ./obj/hugeadm --pool-pages-min 16M:1024
    fi

    $sudo ./obj/hugeadm --explain

    timeout 1h $sudo make $jflags check

    set +x
    echo "success: hugetlbfs" >&2

} 2>&1 >> log | tee -a log
