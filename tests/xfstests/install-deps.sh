#!/bin/bash

set -euo pipefail

. /etc/os-release

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

if [[ "$ID" == "fedora" ]]; then
    (set -x; $sudo dnf -y install \
        acl \
        attr \
        automake \
        bc \
        btrfs-progs-devel \
        dbench \
        dump \
        e2fsprogs \
        fio \
        gawk \
        gcc \
        indent \
        libacl-devel \
        libaio-devel \
        libcap-devel \
        libtool \
        liburing-devel \
        libuuid-devel \
        lvm2 \
        make \
        psmisc \
        python \
        quota \
        sed \
        sqlite \
        xfsdump \
        xfsprogs \
        xfsprogs-devel
    )
elif [[ "$ID_LIKE" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    (set -x; $sudo apt-get -y install \
        attr \
        automake \
        dbench \
        e2fsprogs \
        fio \
        gawk \
        gcc \
        libacl1-dev \
        libaio-dev \
        libcap-dev \
        libgdbm-dev \
        libtool-bin \
        libuuid1 \
        make \
        python3 \
        quota \
        sqlite3 \
        uuid-dev \
        uuid-runtime \
        xfslibs-dev \
        xfsprogs \
     )
else
    echo "Unsupported distro!" >&2
    exit 1
fi
