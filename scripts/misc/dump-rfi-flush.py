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

    print("# Dumping RFI fixup entries")
    print("# Fixup entry    Address          Symbol")
    patched_rfids = {}
    for entry_addr, addr in iter_fixup_section(path, '__rfi_flush_fixup'):
        rfi_addr = addr + (4 * 3)
        patched_rfids[rfi_addr] = True

        symbol, offset = find_addr(syms, addr)
        print(f'{entry_addr:016x} {addr:016x} {symbol}+0x{offset:x}')

    patched = []
    unpatched = []
    cmd = f'ppc64le-objdump -d {path}'
    output = check_output(cmd.split())
    for line in output.decode('utf-8').splitlines():
        if 'rfid' not in line:
            continue

        # c000000000001b78:	24 00 00 4c 	rfid
        words = line.split()
        addr = int(words[0][:-1], 16)
        instr = words[-1]

        symbol, offset = find_addr(syms, addr)
        s = f'{instr:5} at {addr:016x} {symbol}+0x{offset:x}'
        if addr in patched_rfids:
            patched.append(s)
        else:
            unpatched.append(s)

    if len(patched):
        print("\n(h)rfids with a fixup entry:")
        print('\n'.join(patched))

    print("\n(h)rfids with NO fixup entry (may be benign):")
    print('\n'.join(unpatched))

    return 0

sys.exit(main(sys.argv[1:]))
