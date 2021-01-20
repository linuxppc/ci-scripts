#!/usr/bin/python3

import os
import sys
sys.path.append(f'{os.path.dirname(sys.argv[0])}/../../lib')
from dump import *


def iter_extable(vmlinux_path):
    start_addr, offset, size = read_section_info(vmlinux_path, '__ex_table')
    endian = get_endian(vmlinux_path)

    f = open(vmlinux_path, 'rb')

    if endian == 'little':
        fmt = '<ll'
    else:
        fmt = '>ll'

    f.seek(offset)
    data = f.read(size)

    cur_addr = start_addr
    for tupl in struct.iter_unpack(fmt, data):
        val = tupl[0]
        fault_addr = cur_addr + val
        val = tupl[1]
        fixup_addr = cur_addr + val + 4
        yield (cur_addr, fault_addr, fixup_addr)
        cur_addr += 8

def main(args):
    if len(args) == 0:
        print("Usage: %s <vmlinux>" % sys.argv[0], file=sys.stderr)
        return 1

    path = args[0]
    syms = read_symbols(path)

    print("# Dumping exception table entries")

    try:
        for (entry_addr, fault_addr, fixup_addr) in iter_extable(path):
            fault_sym, fault_offset = find_addr(syms, fault_addr)
            fixup_sym, fixup_offset = find_addr(syms, fixup_addr)
            print(f'{entry_addr:016x} {fault_addr:016x} {fault_sym}+0x{fault_offset:x} fixup @ {fixup_addr:016x} {fixup_sym}+0x{fixup_offset:x}')
    except (KeyboardInterrupt, BrokenPipeError):
        pass

    return 0


sys.exit(main(sys.argv[1:]))
