#!/bin/bash

set -euo pipefail

. /etc/os-release

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

if [[ "$ID" == "fedora" ]]; then
    (set -x; $sudo dnf -y install \
        bc \
        binutils \
        bison \
        flex \
        gcc \
        gcc-plugin-devel \
        gmp-devel \
        libmpc-devel \
        openssl-devel \
        ;
    )
elif [[ "${ID_LIKE:-$ID}" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    (set -x; $sudo apt-get -y install gcc binutils bc flex bison)
else
    echo "Unsupported distro!" >&2
    exit 1
fi
