#!/bin/bash

set -euo pipefail

. /etc/os-release

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

if [[ "$ID" == "fedora" ]]; then
    (set -x; $sudo dnf -y install autoconf diffutils file libtool make gcc)
elif [[ "${ID_LIKE:-$ID}" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    (set -x; $sudo apt-get -y install autoconf diffutils file libtool build-essential)
else
    echo "Unsupported distro!" >&2
    exit 1
fi
