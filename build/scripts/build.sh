#!/bin/bash

if [[ -z "$1" ]]; then
    echo "Usage: $0 <target>" >&2
    exit 1
fi

if [[ -z "$SRC" ]]; then
    echo "Error: set SRC to your source tree" >&2
    echo "       eg. make SRC=~/linux ..." >&2
    exit 1
fi

dir="$(dirname "$0")"
script_base="$(realpath "$dir")"
. "$script_base/lib.sh"

IFS=@ read -r task subarch distro version <<< "$1"

image="linuxppc/build:$distro-$version"

SRC="${SRC/#\~/$HOME}"
SRC=$(realpath "$SRC")

alternate_binds=$(get_alternate_binds)

if [[ "$subarch" == "ppc64" ]]; then
    cross="powerpc64-linux-gnu-"
else
    cross="powerpc64le-linux-gnu-"
fi

cmd="$DOCKER run --rm "

if [[ -t 0 ]]; then
    cmd+="-it "
fi

cmd+="--network none "
cmd+="-w /linux "
cmd+="-v $SRC:/linux:ro "

cmd+="$alternate_binds "
cmd+="-e ARCH=powerpc "

if [[ -n $JFACTOR ]]; then
    cmd+="-e JFACTOR=$JFACTOR "
fi

if [[ -n $INSTALL ]]; then
    cmd+="-e INSTALL=$INSTALL "
fi

if [[ -n $QUIET ]]; then
    cmd+="-e QUIET=$QUIET "
fi

if [[ -n $VERBOSE ]]; then
    cmd+="-e VERBOSE=$VERBOSE "
fi

if [[ -n $W ]]; then
    cmd+="-e KBUILD_EXTRA_WARN=$W "
fi

if [[ -n $SPARSE ]]; then
    cmd+="-e SPARSE=$SPARSE "
fi

if [[ -n $PRE_CLEAN ]]; then
    cmd+="-e PRE_CLEAN=$PRE_CLEAN "
fi

if [[ -n $POST_CLEAN ]]; then
    cmd+="-e POST_CLEAN=$POST_CLEAN "
fi

if [[ -n $MODULES ]]; then
    cmd+="-e MODULES=$MODULES "
fi

cmd+="-e CROSS_COMPILE=$cross "

if [[ -n "$KBUILD_BUILD_TIMESTAMP" ]]; then
    cmd+="-e KBUILD_BUILD_TIMESTAMP=$KBUILD_BUILD_TIMESTAMP "
fi

if [[ "$task" == "kernel" ]]; then
    if [[ -z "$DEFCONFIG" ]]; then
        DEFCONFIG="${subarch}_defconfig"
    fi
    cmd+="-e DEFCONFIG=$DEFCONFIG "

    if [[ -n "$MERGE_CONFIG" ]]; then
	cmd+="-e MERGE_CONFIG=$MERGE_CONFIG "
    fi

    if [[ -n "$CLANG" ]]; then
        cmd+="-e CLANG=1 "
    fi
fi

if [[ "$task" == "ppctests" ]]; then
    TARGETS="powerpc"
fi

if [[ -n $TARGETS ]]; then
    cmd+="-e TARGETS=$TARGETS "
fi

output_dir=$(get_output_dir "$script_base" "$subarch" "$distro" "$version" "$task" "$DEFCONFIG" "$TARGETS" "$CLANG")
mkdir -p "$output_dir"

cmd+="-v $output_dir:/output:rw "

user=$(stat -c "%u:%g" $output_dir)
cmd+="-u $user "

if [[ -n "$CCACHE" ]]; then
    cmd+="-v $CCACHE:/ccache "
    cmd+="-e CCACHE_DIR=/ccache "
    cmd+="-e CCACHE=1 "
fi

if [[ -n "$DOCKER_EXTRA_ARGS" ]]; then
    # Can be used for eg. a rootdisk.
    # DOCKER_EXTRA_ARGS="-v /path/to/rootdisk:/path/to/rootdisk:ro"
    cmd+="$DOCKER_EXTRA_ARGS "
fi

cmd+="$image "
cmd+="/bin/container-build.sh $task"

(set -x; $cmd)

exit $?
