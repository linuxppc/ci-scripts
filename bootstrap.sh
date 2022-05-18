#!/usr/bin/env bash
#
set -euo pipefail

. /etc/os-release

echo "########################################"
echo "# Installing basic packages ..."
echo "########################################"

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

if [[ "$ID" == "fedora" ]]; then
    (set -x;
     $sudo dnf -y install \
        expect \
        make \
        wget \
        python3-pexpect \
        tar \
        xz
    )
elif [[ "$ID_LIKE" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    (set -x;
     $sudo apt-get -y install \
        expect \
        make \
        wget \
        python3-pexpect \
        python-is-python3 \
        tar \
        xz-utils
    )
else
    echo "Unsupported distro!" >&2
    exit 1
fi

nproc=$(nproc)

echo "########################################"
echo "# Downloading external dependencies ..."
echo "########################################"
make -j $nproc download

echo "########################################"
echo "# Installing additional packages ..."
echo "########################################"

# No -j because apt/dnf don't like being run in parallel
make prepare

echo "########################################"
echo "# Building tools ..."
echo "########################################"
make -j $nproc build

echo "########################################"
echo "# Bootstrap completed"
echo "########################################"
