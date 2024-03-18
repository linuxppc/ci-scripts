#!/bin/bash

set -euo pipefail

. /etc/os-release

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

if [[ "$ID" == "fedora" ]]; then
    (set -x; $sudo dnf -y install \
        bison \
        bzip2 \
        flex \
        glib2-devel \
        libcap-ng-devel \
        libpmem-devel \
        libseccomp-devel \
        libslirp-devel \
        libudev-devel \
        meson \
        ninja-build \
        pixman-devel
    )
elif [[ "${ID_LIKE:-$ID}" == "debian" ]]; then
    (set -x; $sudo apt-get -y install \
        bison \
        bzip2 \
        flex \
        libcap-ng-dev \
        libglib2.0-dev \
        libpixman-1-dev \
        libseccomp-dev \
        libslirp-dev \
        meson \
        ninja-build
     )
else
    echo "Unsupported distro!" >&2
    exit 1
fi
