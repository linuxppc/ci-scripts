#!/bin/bash

if [[ -z "$1" ]]; then
    echo "Usage: $0 <target>" >&2
    exit 1
fi

dir="$(dirname "$0")"
script_base="$(realpath "$dir")"
. "$script_base/lib.sh"

IFS=@ read -r task subarch distro version <<< "$1"

output_dir=$(get_output_dir "$script_base" "$subarch" "$distro" "$version" "$task" "$DEFCONFIG" "$TARGETS" "$CLANG")

case "$task" in
    prune-kernel)
        if [[ ! -e "$output_dir/Makefile" ]]; then
            # Assume it's already been pruned
            exit 0
        fi

        echo "Pruning non-outputs in $output_dir"

        set -euo pipefail
        cd "$output_dir"
        mkdir -p "artifacts"
        for path in .config vmlinux System.map arch/powerpc/boot/zImage include/config/kernel.release \
                    arch/powerpc/kernel/asm-offsets.s arch/powerpc/boot/uImage modules.tar.bz2 \
                    modules.tar.gz sparse.log log.txt
        do
            if [[ -e "$path" ]]; then
                mv "$path" artifacts/
            fi
        done
        find . -not -path "./artifacts*" -delete
        mv artifacts/.config config
        mv artifacts/* .
        rmdir artifacts
        ;;
    prune-selftests)
        if [[ ! -e "$output_dir/kselftest" ]]; then
            # Assume it's already been pruned
            exit 0
        fi

        echo "Pruning non-outputs in $output_dir"

        set -euo pipefail
        cd "$output_dir"
        if [[ -d install ]]; then
            mv install selftests
            tar -czf selftests.tar.gz selftests
        fi
        find . -not -path "./selftests.tar.gz" -delete
        ;;
    *)
        (set -x ; rm -rf "$output_dir")
        ;;
esac
