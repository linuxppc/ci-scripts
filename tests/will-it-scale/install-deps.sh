#!/bin/bash

set -euo pipefail

. /etc/os-release

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

if [[ "$ID" == "fedora" ]]; then
    (set -x; $sudo dnf -y install gcc hwloc-devel make)
elif [[ "$ID_LIKE" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    (set -x; $sudo apt-get -y install build-essential libhwloc-dev)
else
    echo "Unsupported distro!" >&2
    exit 1
fi
