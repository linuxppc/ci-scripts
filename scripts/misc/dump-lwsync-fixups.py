#!/usr/bin/python3

import os
import sys
sys.path.append(f'{os.path.dirname(sys.argv[0])}/../../lib')
from dump import *


def main(args):
    if len(args) == 0:
        print("Usage: %s <vmlinux>" % sys.argv[0], file=sys.stderr)
        return 1

    path = args[0]
    syms = read_symbols(path)

    print("# Dumping lwsync fixup sites")
    print("# Fixup entry    Address          Symbol")

    try:
        for entry_addr, addr in iter_fixup_section(path, '__lwsync_fixup'):
            symbol, offset = find_addr(syms, addr)
            print(f'{entry_addr:016x} {addr:016x} {symbol}+0x{offset:x}')
    except (KeyboardInterrupt, BrokenPipeError):
        pass

    return 0


sys.exit(main(sys.argv[1:]))
