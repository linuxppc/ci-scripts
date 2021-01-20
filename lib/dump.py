import os
import logging
import struct
import subprocess
from subprocess import check_output
from utils import get_endian


def read_symbols(vmlinux_path):
    last_function = ''
    last_addr = 0

    cmd = 'nm -n %s' % vmlinux_path
    lines = check_output(cmd.split(), stderr=subprocess.STDOUT).decode('utf-8').splitlines()
    if ': no symbols' in lines[0]:
        logging.debug("No symbols found in vmlinux!")
        sys_map = get_system_map()
        if sys_map is None:
            logging.error("No SYSTEM_MAP, can't proceed")
            return None

        lines = open(sys_map).readlines()

    addrs = []
    last_addr = 0
    for line in lines:
        tokens = line.split()
        if len(tokens) == 3:
            addr = int(tokens[0], 16)
            sym_type = tokens[1]
            name = tokens[2]
        elif len(tokens) == 2:
            addr = last_addr
            sym_type = tokens[0]
            name = tokens[1]
        else:
            raise Exception("Couldn't grok nm output")

        addrs.append((addr, name, sym_type))
        last_addr = addr

    return addrs


def find_symbol(symbol_map, name):
    for addr, cur_name, sym_type in symbol_map:
        if cur_name == name:
            return addr

    return None


def find_symbol_and_size(symbol_map, name):
    saddr = None
    i = 0
    for addr, cur_name, sym_type in symbol_map:
        if cur_name == name:
            saddr = addr
            break
        i += 1

    if saddr is None:
        return (None, None)

    i += 1
    if i >= len(symbol_map):
        size = -1
    else:
        size = symbol_map[i][0] - saddr

    return (saddr, size)


def find_addr(symbol_map, addr):
    last_addr = 0
    last_function = ''

    for current_addr, name, sym_type in symbol_map:
        if sym_type.lower() == 'w':
            continue

        if current_addr > addr:
            offset = addr - last_addr
            return (last_function, offset)

        if current_addr == last_addr:
            # If we get multiple symbols for the same addr, use the longest
            if len(name) > len(last_function):
                last_function = name
        else:
            last_function = name

        last_addr = current_addr

    return (addr, 0)


objdump_bin = None

def find_objdump():
    global objdump_bin

    if objdump_bin is not None:
        return objdump_bin

    candidates = ['powerpc64le-linux-gnu-objdump', 'powerpc64-linux-gnu-objdump',
                  'powerpc-linux-gnu-objdump', 'powerpc64le-objdump', 'powerpc64-objdump',
                  'powerpc-objdump', 'ppc64le-objdump', 'ppc64-objdump', 'ppc-objdump',
                  'objdump']

    objdump = os.environ.get('PPC_OBJDUMP', None)
    if objdump is not None:
        candidates.insert(0, objdump)

    for objdump in candidates:
        try:
            check_output([objdump, '-v'])
        except (subprocess.CalledProcessError, OSError) as e:
            # Uncomment if you're having trouble finding a working objdump
            #print(e)
            pass
        else:
            objdump_bin = objdump
            return objdump_bin

    raise Exception("Couldn't find working objdump!")


def find_section_by_addr(vmlinux_path, start_vaddr, end_vaddr):
    objdump = find_objdump()
    cmd = f'{objdump} -w -h {vmlinux_path}'
    output = check_output(cmd.split())

    for line in output.decode('utf-8').splitlines():
        tokens = line.split()
        if len(tokens) < 6 or tokens[0] == 'Idx':
            continue

        section_size = int(tokens[2], 16)
        section_start_vaddr = int(tokens[3], 16)
        section_offset = int(tokens[5], 16)
        section_end_vaddr = section_start_vaddr + section_size

        if start_vaddr >= section_start_vaddr and \
           end_vaddr <= section_end_vaddr:
            return section_offset + (start_vaddr - section_start_vaddr)

    return None


def read_section_info(vmlinux_path, section_name):
    objdump = find_objdump()
    cmd = f'{objdump} -h -j {section_name} {vmlinux_path}'
    output = check_output(cmd.split())

    for line in output.decode('utf-8').splitlines():
        if section_name not in line:
            continue

        tokens = line.split()
        size = int(tokens[2], 16)
        start_addr = int(tokens[3], 16)
        offset = int(tokens[5], 16)
        return (start_addr, offset, size)

    raise Exception("Couldn't parse vmlinux")


def iter_fixup_section(vmlinux_path, section):
    start_addr, offset, size = read_section_info(vmlinux_path, section)
    endian = get_endian(vmlinux_path)

    f = open(vmlinux_path, 'rb')

    if endian == 'little':
        fmt = '<q'
    else:
        fmt = '>q'

    f.seek(offset)
    data = f.read(size)

    cur_addr = start_addr
    for tupl in struct.iter_unpack(fmt, data):
        val = tupl[0]
        addr = cur_addr + val
        yield (cur_addr, addr)
        cur_addr += 8


def iter_nospec_fixups(vmlinux_path):
    # Uses a single FTR_ENTRY_OFFSET
    return iter_fixup_section(vmlinux_path, '__spec_barrier_fixup')


def iter_rfi_fixups(vmlinux_path):
    # Uses a single FTR_ENTRY_OFFSET
    return iter_fixup_section(vmlinux_path, '__rfi_flush_fixup')


def iter_stf_entry_barrier_fixups(vmlinux_path):
    # Uses a single FTR_ENTRY_OFFSET
    return iter_fixup_section(vmlinux_path, '__stf_entry_barrier_fixup')


def iter_stf_exit_barrier_fixups(vmlinux_path):
    # Uses a single FTR_ENTRY_OFFSET
    return iter_fixup_section(vmlinux_path, '__stf_exit_barrier_fixup')
