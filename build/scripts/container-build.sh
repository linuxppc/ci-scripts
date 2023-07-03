#!/bin/bash

JFACTOR=${JFACTOR:-1}

gcc_version=$(${CROSS_COMPILE}gcc --version | head -1)
ld_version=$(${CROSS_COMPILE}ld --version | head -1)

echo "## VERSION       = $(cat /VERSION)"
echo "## ARCH          = $ARCH"
echo "## CROSS_COMPILE = $CROSS_COMPILE"
echo "## gcc           = $gcc_version"

if [[ -n "$CLANG" ]]; then
       clang_version=$(clang --version | head -1)
       echo "## clang         = $clang_version"
fi

echo "## ld            = $ld_version"
echo "## JFACTOR       = $JFACTOR"

if [[ -n "$KBUILD_BUILD_TIMESTAMP" ]]; then
    echo "## KBUILD_TS     = $KBUILD_BUILD_TIMESTAMP"
fi

if [[ -n "$KBUILD_EXTRA_WARN" ]]; then
    echo "## EXTRA_WARN    = $KBUILD_EXTRA_WARN"
fi

export KBUILD_OUTPUT=/output

if [[ -n "$QUIET" ]]; then
    quiet="-s"
fi

if [[ -n "$VERBOSE" ]]; then
    verbose="V=1"
fi

rc=0

if [[ "$1" == "kernel" ]]; then
    cc="${CROSS_COMPILE}gcc"
    if [[ -n "$CLANG" ]]; then
        cc="clang"
    fi

    if [[ "$CCACHE" -eq 1 ]]; then
        cc="ccache $cc"
    fi

    cc="CC=$cc"

    if [[ -n "$PRE_CLEAN" ]]; then
        (set -x; make $verbose $quiet "$cc" clean)
    fi

    if [[ "$DEFCONFIG" == .config* || "$DEFCONFIG" == *.config ]]; then
        echo "## Using existing config $DEFCONFIG"
        cp -f "$DEFCONFIG" /output/.config || exit 1
    else
        # Strip off any suffix after the first '+' used for unique naming
        DEFCONFIG="${DEFCONFIG%%+*}"
        echo "## DEFCONFIG     = $DEFCONFIG"
        (set -x; make $verbose $quiet "$cc" $DEFCONFIG)
    fi

    if [[ -n "$MERGE_CONFIG" ]]; then
        echo "## MERGE_CONFIG  = $MERGE_CONFIG"

        # Split the comma separated list
        IFS=',' read -r -a configs <<< "$MERGE_CONFIG"

        # merge_config.sh always writes its TMP files to $PWD, so we have to
        # change into /output before running it.
        (cd /output; set -x; /linux/scripts/kconfig/merge_config.sh -m .config ${configs[@]})
        (set -x; make $verbose $quiet "$cc" olddefconfig)
    fi

    rc=$?

    if [[ -n "$MOD2YES" ]]; then
        (set -x; make $verbose $quiet "$cc" mod2yesconfig)
    fi

    if [[ -n "$REPRODUCIBLE" ]]; then
        # Check for options that defeat reproducible builds
        grep \
            -e CONFIG_IKCONFIG=y \
            -e CONFIG_LOCALVERSION_AUTO=y \
            -e CONFIG_IKHEADERS=y \
            /output/.config
        if [[ $? -eq 0 ]]; then
            echo "!! Reproducible build specified, but the above options may prevent reproducibility."
        fi
    fi

    if [[ $rc -eq 0 ]]; then
        if [[ -n "$SPARSE" ]]; then
            rm -f /output/sparse.log
            touch /output/sparse.log
            (set -x; make C=$SPARSE CF=">> /output/sparse.log 2>&1" $verbose $quiet "$cc" -j $JFACTOR)

            rc=$?

            if [[ $rc -eq 0 && -x arch/powerpc/tools/check-sparse-log.sh ]]; then
                arch/powerpc/tools/check-sparse-log.sh /output/sparse.log
                rc=$?
            fi
        else
            (set -x; make $verbose $quiet "$cc" -j $JFACTOR)
            rc=$?
        fi
    fi

    if [[ $rc -eq 0 && -n "$MODULES" ]]; then
        if grep CONFIG_MODULES=y /output/.config > /dev/null; then
            echo "## Installing modules"

            mod_path=/output/modules
            # Clean out any old modules
            rm -rf $mod_path

            (set -x; make $verbose $quiet -j $JFACTOR "$cc" INSTALL_MOD_PATH=$mod_path modules_install)
            rc=$?
            if [[ $rc -eq 0 ]]; then
                tar -cjf /output/modules.tar.bz2 -C $mod_path lib
            fi
        else
            echo "## Modules not configured"
        fi
    fi

    echo "## Kernel build completed rc = $rc"

    /linux/scripts/clang-tools/gen_compile_commands.py -o /output/compile_commands.json /output > /dev/null 2>&1 || true

    if [[ -f /output/vmlinux ]]; then
        size /output/vmlinux
    fi

    if [[ "$CCACHE" -eq 1 ]]; then
        ccache -s
    fi

    if [[ -n "$POST_CLEAN" ]]; then
        (set -x; make $verbose $quiet "$cc" clean)
    fi
elif [[ "$1" == "docs" ]]; then
    (set -x -o pipefail; make $verbose $quiet -j $JFACTOR htmldocs 2>&1 | tee /output/docs.log)
    rc=$?

    if [[ $rc -eq 0 ]]; then
        grep -i "\bpowerpc\b.*warning" /output/docs.log
        if [[ $? -eq 0 ]]; then
            echo "## Error, saw powerpc errors/warnings in docs build!"
            rc=1
        fi
    fi
elif [[ "$1" == "perf" ]]; then
    cmd="make $quiet -C tools/perf O=/output"

    if [[ $(uname -m) != "ppc64le" ]]; then
        cmd+=" NO_LIBELF=1 NO_LIBTRACEEVENT=1"
    fi

    if [[ -n "$PRE_CLEAN" ]]; then
        (set -x; $cmd clean)
    fi

    (set -x; $cmd)
    rc=$?
    echo "## tools/perf build completed rc = $rc"

    if [[ -n "$POST_CLEAN" ]]; then
        (set -x; $cmd clean)
    fi
else
    # Workaround 303e6218ecec ("selftests: Fix O= and KBUILD_OUTPUT handling for relative paths")
    export abs_objtree=$KBUILD_OUTPUT

    cmd="make $quiet -j $JFACTOR -C tools/testing/selftests"

    if [[ "$1" == "ppctests" ]]; then
        TARGETS="powerpc"
    fi

    if [[ -n "$TARGETS" ]]; then
        echo "## TARGETS       = $TARGETS"
        cmd+=" TARGETS=$TARGETS"
    fi

    if [[ -n "$INSTALL" ]]; then
       echo "## INSTALL       = $INSTALL"
       cmd+=" INSTALL_PATH=/output/install install"
    fi

    which dpkg-query > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        libc_version=$(dpkg-query --show --showformat='${Version}' libc6)
        echo "## libc          = $libc_version"
    fi

    if [[ -n "$PRE_CLEAN" ]]; then
        (set -x; $cmd clean)
    fi

    (set -x; make $quiet -j $JFACTOR headers)
    (set -x; $cmd)
    rc=$?
    echo "## Selftest build completed rc = $rc"
    bins=$(find /output ! -path "/output/install/*" -type f -perm -u+x | wc -l)
    echo "## Found $bins binaries"

    if [[ -n "$POST_CLEAN" ]]; then
        (set -x; $cmd clean)
    fi
fi

if [[ $rc -ne 0 ]]; then
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!! Error build failed rc $rc"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
else
    echo "## Build completed OK"
fi

exit $rc
