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

image="linuxppc/build:$distro-$version"

if [[ "$distro" == "fedora" ]]; then
    from="registry.fedoraproject.org/$distro:$version"
elif [[ "$distro" == "docs" ]]; then
    from="public.ecr.aws/ubuntu/ubuntu:$version"
elif [[ "$distro" == "allcross" ]]; then
    from="public.ecr.aws/debian/debian:$version"
elif [[ "$distro" == "korg" ]]; then
    # Use an older distro for the 5.x toolchains.
    if [[ "$version" == 5.* ]]; then
        from="public.ecr.aws/docker/library/ubuntu:16.04"
    else
        from="public.ecr.aws/ubuntu/ubuntu:24.04"
    fi
elif [[ "$distro" == "ubuntu" && "$version" == 16.* ]]; then
    from="public.ecr.aws/docker/library/ubuntu:16.04"
else
    from="public.ecr.aws/$distro/$distro:$version"
fi

if [[ "$task" == "image" ]]; then
    cmd="$DOCKER images -q --filter=reference=$image"
    echo "+ $cmd" # fake set -x display
    exists=$($cmd)
    if [[ -n "$exists" ]]; then
        exit 0
    fi
elif [[ "$task" == "pull-image" ]]; then
    arch_image="$image-$(uname -m)"
    cmd="$DOCKER pull ghcr.io/$arch_image"
    (set -x; $cmd)

    if [[ $? -ne 0 ]]; then
	echo "Error: pulling $image?" >&2
	exit $?
    fi

    # Tag the arch specific image with the generic tag
    cmd="$DOCKER tag $arch_image $image"
    (set -x; $cmd)
    if [[ $? -ne 0 ]]; then
        echo "Error: tagging $arch_image as $image?" >&2
        exit 1
    fi

    # Remove the arch tag (not the whole image)
    cmd="$DOCKER rmi $arch_image"
    (set -x; $cmd)
    if [[ $? -ne 0 ]]; then
        echo "Error: untagging $arch_image?" >&2
        exit 1
    fi

    exit 0
elif [[ "$task" == "push-image" ]]; then
    if [[ -n "$DOCKER_PASSWORD" && -n "$DOCKER_USER" ]]; then
	cmd="$DOCKER login -u $DOCKER_USER -p $DOCKER_PASSWORD"
	(set -x; $cmd)
    fi

    # Temporarily tag the image with the arch
    arch_image="ghcr.io/$image-$(uname -m)"
    cmd="$DOCKER tag $image $arch_image"
    (set -x; $cmd)
    if [[ $? -ne 0 ]]; then
        echo "Error: tagging $image as $arch_image?" >&2
        exit 1
    fi

    cmd="$DOCKER push $arch_image"
    (set -x; $cmd)
    if [[ $? -ne 0 ]]; then
        echo "Error: pushing $arch_image?" >&2
        exit 1
    fi

    # Remove the arch tag (not the whole image)
    cmd="$DOCKER rmi $arch_image"
    (set -x; $cmd)
    if [[ $? -ne 0 ]]; then
        echo "Error: untagging $arch_image?" >&2
        exit 1
    fi

    exit 0
elif [[ "$task" == "pull-base-image" ]]; then
    cmd="$DOCKER pull $from"
    (set -x; $cmd)
    exit $?
fi

cmd="$DOCKER build -f $distro/Dockerfile "

if [[ -n "$http_proxy" ]]; then
    cmd+="--build-arg http_proxy=$http_proxy "
fi

if [[ -n "$https_proxy" ]]; then
    cmd+="--build-arg https_proxy=$https_proxy "
fi

if [[ "$distro" == "korg" ]]; then
    cmd+="--build-arg compiler_version=$version "
    arch=$(uname -m)
    cmd+="--build-arg base_url=https://mirrors.edge.kernel.org/pub/tools/crosstool/files/bin/${arch}/${version}/ "
    cmd+="--build-arg tar_file=${arch}-gcc-${version}-nolibc-powerpc64-linux.tar.xz "
fi

cmd+="--build-arg from=$from "
cmd+="--build-arg apt_mirror=$APT_MIRROR "
cmd+="-t $image ."

(set -x; $cmd)

exit $?
