#!/bin/bash

if [[ -z "$1" ]]; then
    echo "Usage: $0 <target>" >&2
    exit 1
fi

dir="$(dirname "$0")"
script_base="$(realpath "$dir")"
. "$script_base/lib.sh"

IFS=@ read -r task subarch distro version <<< "$1"

output_dir=$(get_output_dir "$script_base" "$subarch" "$distro" "$version" "$task" "$DEFCONFIG" "$TARGETS" "$CLANG" "")

(set -x ; rm -rf "$output_dir")
