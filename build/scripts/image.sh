#!/bin/bash

if [[ -z "$1" ]]; then
    echo "Usage: $0 <target>" >&2
    exit 1
fi

dir="$(dirname "$0")"
script_base="$(realpath "$dir")"
. "$script_base/lib.sh"

IFS=@ read -r task subarch distro version <<< "$1"

image="linuxppc/build:$distro-$version"

if [[ "$task" == "image" ]]; then
    exists=$($DOCKER images -q --filter=reference="$image")
    if [[ -n "$exists" ]]; then
        exit 0
    fi
elif [[ "$task" == "pull-image" ]]; then
    arch_image="$image-$(uname -m)"
    cmd="$DOCKER pull $arch_image"
    (set -x; $cmd)

    if [[ $? -ne 0 ]]; then
	echo "Error: pulling $image?" >&2
	exit $?
    fi

    cmd="$DOCKER tag $arch_image $image"
    (set -x; $cmd)

    exit $?
elif [[ "$task" == "push-image" ]]; then
    if [[ -n "$DOCKER_PASSWORD" && -n "$DOCKER_USER" ]]; then
	cmd="$DOCKER login -u $DOCKER_USER -p $DOCKER_PASSWORD"
	(set -x; $cmd)
    fi

    image="$image-$(uname -m)"
    cmd="$DOCKER push $image"
    (set -x; $cmd)
    exit $?
fi

cmd="$DOCKER build --pull -f $distro/Dockerfile "

if [[ -n "$http_proxy" ]]; then
    cmd+="--build-arg http_proxy=$http_proxy "
fi

if [[ -n "$https_proxy" ]]; then
    cmd+="--build-arg https_proxy=$https_proxy "
fi

if [[ -z "$UID" ]]; then
    UID=$(id -u)
fi

if [[ -z "$GID" ]]; then
    GID=$(id -g)
fi

from="$distro:$version"

if [[ "$distro" == "docs" ]]; then
    from="ubuntu:$version"
elif [[ "$distro" == "korg" ]]; then
    cmd+="--build-arg compiler_version=$version "

    arch=$(uname -m)

    cmd+="--build-arg base_url=https://mirrors.edge.kernel.org/pub/tools/crosstool/files/bin/${arch}/${version}/ "
    if [[ "$version" == "4.6.3" ]]; then
	cmd+="--build-arg tar_file=${arch}-gcc-${version}-nolibc_powerpc64-linux.tar.xz "
    else
	cmd+="--build-arg tar_file=${arch}-gcc-${version}-nolibc-powerpc64-linux.tar.xz "
    fi

    # Use an older distro for the 4.x/5.x toolchains.
    if [[ "$version" == 4.* || "$version" == 5.* ]]; then
	from="ubuntu:16.04"
    else
	from="ubuntu:20.04"
    fi
fi

cmd+="--build-arg uid=$UID "
cmd+="--build-arg gid=$GID "
cmd+="--build-arg from=$from "
cmd+="--build-arg apt_mirror=$APT_MIRROR "
cmd+="-t $image-$(uname -m) "
cmd+="-t $image ."

(set -x; $cmd)

exit $?
