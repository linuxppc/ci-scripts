#!/usr/bin/python3

import os
import sys
sys.path.append(f'{os.path.dirname(sys.argv[0])}/../../lib')
from dump import *


def main(args):
    if len(args) == 0:
        print("Usage: %s <vmlinux>" % sys.argv[0], file=sys.stderr)
        return 1

    vmlinux_path = args[0]
    syms = read_symbols(vmlinux_path)

    start_vaddr, size = find_symbol_and_size(syms, 'sys_call_table')
    if start_vaddr is None:
        print("Error: couldn't find sys_call_table?!")
        return 1

    if size == -1:
        print("Error: couldn't find size of sys_call_table?!")
        return 1

    endian = get_endian(vmlinux_path)

    if endian == 'little':
        fmt = '<Q'
        inst_fmt = '<I'
    else:
        fmt = '>Q'
        inst_fmt = '>I'

    end_vaddr = start_vaddr + size
    offset = find_section_by_addr(vmlinux_path, start_vaddr, end_vaddr)
    if offset is None:
        return

    f = open(vmlinux_path, 'rb')
    f.seek(offset)
    data = f.read(end_vaddr - start_vaddr)

    print("# Dumping system call table")
    print("# Entry          Address          Symbol")

    addr = start_vaddr

    try:
        num = 0
        for tupl in struct.iter_unpack(fmt, data):
            val = tupl[0]

            symbol, offset = find_addr(syms, val)
            print(f'{num:03} {addr:016x} {val:016x} {symbol}+0x{offset:x}')
            addr += 8
            num += 1

    except (KeyboardInterrupt, BrokenPipeError):
        pass

    return 0


sys.exit(main(sys.argv[1:]))
