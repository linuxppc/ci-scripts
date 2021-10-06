#!/bin/bash

function get_alternate_binds()
{
    local alternates
    local git_dir

    git_dir=$(cd $SRC; git rev-parse --absolute-git-dir)
    alternates="$git_dir/objects/info/alternates"
    if [[ -r "$alternates" ]]; then
        for line in $(cat "$alternates")
        do
            echo "-v $line:$line:ro "
        done
    fi
}

function get_output_dir()
{
    local script_base="$1"
    local subarch="$2"
    local distro="$3"
    local version="$4"
    local task="$5"
    local defconfig="$6"
    local targets="$7"
    local clang="$8"
    local d

    if [[ -z "$script_base" || -z "$subarch" || -z "$distro" || -z "$version" ]]; then
        echo "Error: not enough arguments to get_output_dir()" >&2
        return 1
    fi

    if [[ -n "$CI_OUTPUT" ]]; then
        d="$CI_OUTPUT/$subarch@$distro@$version"
    else
        d="$script_base/../output/$subarch@$distro@$version"
    fi

    case "$task" in
        kernel) ;&
        clean-kernel)
            if [[ -n "$defconfig" ]]; then
                defconfig="${defconfig//\//_}"
                d="$d/$defconfig"
            fi
            ;;
        ppctests) ;&
        selftests) ;&
        clean-selftests)
            if [[ -n "$targets" ]]; then
                targets=${targets// /_}
                targets=${targets//\//_}
                d="$d/selftests_$targets"
            else
                d="$d/selftests"
            fi
            ;;
        perf) ;&
        clean-perf)
            d="$d/perf"
            ;;
    esac

    if [[ -n "$clang" ]]; then
	d="${d}_clang"
    fi

    echo "$d"

    return 0
}

grep "^NAME=Fedora$" /etc/os-release > /dev/null
if [[ $? -eq 0 ]]; then
    DOCKER="podman"
    PODMAN_OPTS="--security-opt label=disable --userns=keep-id"
else
    DOCKER="docker"
    PODMAN_OPTS=""
fi
