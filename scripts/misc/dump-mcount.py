#!/usr/bin/python3

import os
import sys
sys.path.append(f'{os.path.dirname(sys.argv[0])}/../../lib')
from dump import *


def iter_mcount(vmlinux_path, symbol_map):
    start_vaddr = find_symbol(symbol_map, '__start_mcount_loc')
    end_vaddr = find_symbol(symbol_map, '__stop_mcount_loc')

    endian = get_endian(vmlinux_path)

    if endian == 'little':
        fmt = '<Q'
        inst_fmt = '<I'
    else:
        fmt = '>Q'
        inst_fmt = '>I'

    offset = find_section_by_addr(vmlinux_path, start_vaddr, end_vaddr)
    if offset is None:
        return

    f = open(vmlinux_path, 'rb')
    f.seek(offset)
    data = f.read(end_vaddr - start_vaddr)

    addr = start_vaddr
    for tupl in struct.iter_unpack(fmt, data):
        val = tupl[0]

        offset = find_section_by_addr(vmlinux_path, val, val + 4)
        f.seek(offset)
        instruction = struct.unpack(inst_fmt, f.read(4))[0]
        yield (addr, val, instruction)
        addr += 8


def main(args):
    if len(args) == 0:
        print(f'Usage: {sys.argv[0]} <vmlinux>', file=sys.stderr)
        return 1

    path = args[0]
    syms = read_symbols(path)

    print("# Dumping mcount records")
    print("# Fixup entry    Address          Inst     Symbol")

    start = find_symbol(syms, '__start_mcount_loc')
    end = find_symbol(syms, '__stop_mcount_loc')

    try:
        for (entry_addr, mcount_addr, instruction) in iter_mcount(path, syms):
            symbol, offset = find_addr(syms, mcount_addr)
            print(f'{entry_addr:016x} {mcount_addr:016x} {instruction:08x} {symbol}+0x{offset:x}')
    except (KeyboardInterrupt, BrokenPipeError):
        pass

    return 0


sys.exit(main(sys.argv[1:]))
