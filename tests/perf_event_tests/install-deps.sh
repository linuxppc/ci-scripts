#!/bin/bash

set -euo pipefail

. /etc/os-release

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

if [[ "$ID" == "fedora" ]]; then
    (set -x; $sudo dnf -y install make gcc)
elif [[ "$ID_LIKE" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    (set -x; $sudo apt-get -y install build-essential)
else
    echo "Unsupported distro!" >&2
    exit 1
fi
