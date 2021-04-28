#!/bin/bash

PACKAGES=""

machine=$(uname -m)

PACKAGES+=" gcc-powerpc-linux-gnu g++-powerpc-linux-gnu"

. /etc/os-release

# We could use crossbuild-essential-xxx but that breaks on 14.04
if [[ "$VERSION_ID" == "14.04" ]]; then
    PACKAGES+=" gcc-4.8-multilib-powerpc-linux-gnu"
elif [[ "$VERSION_ID" == "16.04" ]]; then
    PACKAGES+=" gcc-5-multilib-powerpc-linux-gnu"
elif [[ "$VERSION_ID" == "18.04" ]]; then
    PACKAGES+=" gcc-7-multilib-powerpc-linux-gnu"
elif [[ "$VERSION_ID" == "18.10" ]]; then
    PACKAGES+=" gcc-8-multilib-powerpc-linux-gnu"
elif [[ "$VERSION_ID" == "19.04" ]]; then
    PACKAGES+=" gcc-8-multilib-powerpc-linux-gnu"
elif [[ "$VERSION_ID" == "20.04" ]]; then
    PACKAGES+=" gcc-9-multilib-powerpc-linux-gnu"

    if [[ "$machine" != "x86_64" ]]; then
        PACKAGES+=" crossbuild-essential-amd64"
    fi
elif [[ "$VERSION_ID" == "20.10" ]]; then
    PACKAGES+=" gcc-10-multilib-powerpc-linux-gnu"
elif [[ "$VERSION_ID" == "21.04" ]]; then
    PACKAGES+=" gcc-10-multilib-powerpc-linux-gnu"
else
    PACKAGES+=" crossbuild-essential-powerpc"
fi

major="${VERSION_ID%%.*}"
if [[ $major -ge 18 ]]; then
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
else
    PACKAGES+=" gcc-powerpc64le-linux-gnu g++-powerpc64le-linux-gnu"
fi

echo $PACKAGES
