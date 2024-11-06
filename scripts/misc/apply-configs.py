#!/usr/bin/env python3
#
# Apply configs from etc/configs/ to the local kernel tree.
#
# eg.
# $ cd ~/linux
# $ make ppc64le_defconfig
# $ ~/ci-scripts/scripts/misc/apply-configs.py 4k-pages compat-y
# $ make olddefconfig
# 
# Or a group of configs defined in configs.py:
#
# $ ~/ci-scripts/scripts/misc/apply-configs.py guest_configs

 
from subprocess import run
import os, sys

base_dir = os.path.realpath(f'{os.path.dirname(os.path.realpath(sys.argv[0]))}/../..')
sys.path.append(f'{base_dir}/lib')

import configs


def main(args):
    if len(args) == 0:
        print('Usage: apply-configs.py (config group|config file)+')
        return False

    names = []
    for arg in args:
        try:
            group = getattr(configs, arg)
        except AttributeError:
            names.append(arg)
        else:
            names.extend(group)

    src_dir = os.getcwd()
    paths = []
    for name in names:
        # Look in source tree first, which must be current directory
        full_path = f'{src_dir}/{name}'
        if os.path.exists(full_path):
            paths.append((name, full_path))
            continue

        full_path = f'{base_dir}/etc/configs/{name}'
        if not name.endswith('.config'):
            full_path += '.config'

        if not os.path.exists(full_path):
            print(f'Error: unable to find {name}')
            return False

        paths.append((name, full_path))

    kbuild_output = os.environ.get('KBUILD_OUTPUT', None)
    if kbuild_output:
        # merge_config.sh writes its TMP files to $PWD, so change into KBUILD_OUTPUT
        os.chdir(kbuild_output)

    for name, path in paths:
        print(f'Merging {name} ...')
        rc = run([f'{src_dir}/scripts/kconfig/merge_config.sh', '-m', '.config', path])
        if rc.returncode != 0:
            print(f'Error: failed merging {name}')
            return False

    return True


sys.exit(0 if main(sys.argv[1:]) else 1)
