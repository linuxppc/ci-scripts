#!/bin/bash

if [[ -z "$1" ]]; then
    echo "Usage: $0 <target>" >&2
    exit 1
fi

dir="$(dirname "$0")"
script_base="$(realpath "$dir")"
. "$script_base/lib.sh"

IFS=@ read -r task subarch distro version <<< "$1"

if [[ -z "$version" ]]; then
    version=$(get_default_version $distro)
fi

image="docker.io/linuxppc/build:$distro-$version"

if [[ "$task" == "image" ]]; then
    cmd="$DOCKER images -q --filter=reference=$image"
    echo "+ $cmd" # fake set -x display
    exists=$($cmd)
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

from="docker.io/$distro:$version"

if [[ "$distro" == "docs" ]]; then
    from="docker.io/ubuntu:$version"
elif [[ "$distro" == "korg" ]]; then
    cmd+="--build-arg compiler_version=$version "

    arch=$(uname -m)

    cmd+="--build-arg base_url=https://mirrors.edge.kernel.org/pub/tools/crosstool/files/bin/${arch}/${version}/ "
    cmd+="--build-arg tar_file=${arch}-gcc-${version}-nolibc-powerpc64-linux.tar.xz "

    # Use an older distro for the 5.x toolchains.
    if [[ "$version" == 5.* ]]; then
	from="docker.io/ubuntu:16.04"
    else
	from="docker.io/ubuntu:20.04"
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
