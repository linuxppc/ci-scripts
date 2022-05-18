#!/bin/bash

set -euo pipefail

. /etc/os-release

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

if [[ "$ID" == "fedora" ]]; then
    (set -x; $sudo dnf -y install gcc)
elif [[ "$ID_LIKE" == "debian" ]]; then
    (set -x; $sudo apt-get -y install gcc)
else
    echo "Unsupported distro!" >&2
    exit 1
fi
