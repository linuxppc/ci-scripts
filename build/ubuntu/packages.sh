#!/bin/bash

PACKAGES=""

machine=$(uname -m)

. /etc/os-release

major="${VERSION_ID%%.*}"

if [[ "$major" -ge 21 ]]; then
    PACKAGES+=" clang llvm"
fi

if [[ "$machine" == "ppc64le" ]]; then
    PACKAGES+=" libcap-dev"
    PACKAGES+=" libcap-ng-dev"
    PACKAGES+=" libnuma-dev"
    PACKAGES+=" libpopt-dev"
    PACKAGES+=" libhugetlbfs-dev"
    PACKAGES+=" libmnl-dev"
    PACKAGES+=" libmount-dev"

    # For the x86_64 container
    if [[ "$VERSION_ID" == "21.10" ]]; then
        PACKAGES+=" crossbuild-essential-amd64"
    fi
else
    PACKAGES+=" gcc-powerpc64le-linux-gnu g++-powerpc64le-linux-gnu"
fi

echo $PACKAGES
