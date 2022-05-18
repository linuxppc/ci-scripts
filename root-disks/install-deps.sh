#!/bin/bash

set -euo pipefail

. /etc/os-release

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

if [[ "$ID" == "fedora" ]]; then
   package_manager="dnf"
elif [[ "$ID_LIKE" == "debian" ]]; then
   package_manager="apt-get"
else
    echo "Unsupported distro!" >&2
    exit 1
fi

(set -x; $sudo $package_manager -y install \
    cloud-utils \
    genisoimage
)
