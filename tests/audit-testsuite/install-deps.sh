#!/bin/bash

set -euo pipefail

. /etc/os-release

sudo=""
if [[ $(id -u) != 0 ]]; then
    sudo="sudo"
fi

if [[ "$ID" == "fedora" ]]; then
    (set -x; \
        $sudo dnf -y install \
            audit \
            gcc \
            glibc \
            glibc-devel \
            perl \
            perl-Test \
            perl-Test-Harness \
            perl-File-Which \
            perl-Time-HiRes \
            nmap-ncat \
            psmisc
    )
elif [[ "${ID_LIKE:-$ID}" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    (set -x; \
        $sudo apt-get -y install \
            auditd \
            build-essential \
            libc6 \
            libc6-dev \
            perl-modules \
            netcat \
            psmisc
    )
else
    echo "Unsupported distro!" >&2
    exit 1
fi
