#!/bin/bash

set -euo pipefail

. /etc/os-release

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

if [[ "$ID" == "fedora" ]]; then
    (set -x; $sudo dnf -y install \
        autoconf \
        automake \
        diffutils \
        file \
        gcc \
        libtool \
        openssl \
        pkgconf-pkg-config \
        util-linux
    )
elif [[ "$ID_LIKE" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    (set -x; $sudo apt-get -y install autoconf \
        automake \
        bsdextrautils \
        build-essential \
        diffutils \
        file \
        libtool \
        openssl \
        pkg-config
     )
else
    echo "Unsupported distro!" >&2
    exit 1
fi
