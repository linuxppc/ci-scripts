#!/usr/bin/python3

import os
import sys
sys.path.append(f'{os.path.dirname(sys.argv[0])}/../../lib')
from dump import *
import subprocess
from tempfile import mkstemp


def iter_fixups(vmlinux_path, section):
    start_addr, offset, size = read_section_info(vmlinux_path, section)
    endian = get_endian(vmlinux_path)

    f = open(vmlinux_path, 'rb')

    fmt = 'qqqqqq'
    if endian == 'little':
        fmt = f'<{fmt}'
    else:
        fmt = f'>{fmt}'

    f.seek(offset)
    data = f.read(size)

    cur_addr = start_addr
    for tupl in struct.iter_unpack(fmt, data):
        mask = tupl[0]
        ftr_val = tupl[1]

        start = cur_addr + tupl[2]
        end = cur_addr + tupl[3]
        alt_start = cur_addr + tupl[4]
        alt_end = cur_addr + tupl[5]
        yield (cur_addr, mask, ftr_val, start, end, alt_start, alt_end)
        cur_addr += 6 * 8


cpu_features = [
    (0x0000000000000001, 'CPU_FTR_COHERENT_ICACHE'),
    (0x0000000000000002, 'CPU_FTR_ALTIVEC'),
    (0x0000000000000004, 'CPU_FTR_DBELL'),
    (0x0000000000000008, 'CPU_FTR_CAN_NAP'),
    (0x0000000000000010, 'CPU_FTR_DEBUG_LVL_EXC'),
    (0x0000000000000020, 'CPU_FTR_NODSISRALIGN'),
    (0x0000000000000040, 'CPU_FTR_FPU_UNAVAILABLE'),
    (0x0000000000000080, 'CPU_FTR_LWSYNC'),
    (0x0000000000000100, 'CPU_FTR_NOEXECUTE'),
    (0x0000000000000200, 'CPU_FTR_EMB_HV'),
    (0x0000000000001000, 'CPU_FTR_REAL_LE'),
    (0x0000000000002000, 'CPU_FTR_HVMODE'),
    (0x0000000000008000, 'CPU_FTR_ARCH_206'),
    (0x0000000000010000, 'CPU_FTR_ARCH_207S'),
    (0x0000000000020000, 'CPU_FTR_ARCH_300'),
    (0x0000000000040000, 'CPU_FTR_MMCRA'),
    (0x0000000000080000, 'CPU_FTR_CTRL'),
    (0x0000000000100000, 'CPU_FTR_SMT'),
    (0x0000000000200000, 'CPU_FTR_PAUSE_ZERO'),
    (0x0000000000400000, 'CPU_FTR_PURR'),
    (0x0000000000800000, 'CPU_FTR_CELL_TB_BUG'),
    (0x0000000001000000, 'CPU_FTR_SPURR'),
    (0x0000000002000000, 'CPU_FTR_DSCR'),
    (0x0000000004000000, 'CPU_FTR_VSX'),
    (0x0000000008000000, 'CPU_FTR_SAO'),
    (0x0000000010000000, 'CPU_FTR_CP_USE_DCBTZ'),
    (0x0000000020000000, 'CPU_FTR_UNALIGNED_LD_STD'),
    (0x0000000040000000, 'CPU_FTR_ASYM_SMT'),
    (0x0000000080000000, 'CPU_FTR_STCX_CHECKS_ADDRESS'),
    (0x0000000100000000, 'CPU_FTR_POPCNTB'),
    (0x0000000200000000, 'CPU_FTR_POPCNTD'),
    (0x0000000400000000, 'CPU_FTR_PKEY'),
    (0x0000000800000000, 'CPU_FTR_VMX_COPY'),
    (0x0000001000000000, 'CPU_FTR_TM'),
    (0x0000002000000000, 'CPU_FTR_CFAR'),
    (0x0000004000000000, 'CPU_FTR_HAS_PPR'),
    (0x0000008000000000, 'CPU_FTR_DAWR'),
    (0x0000010000000000, 'CPU_FTR_DABRX'),
    (0x0000020000000000, 'CPU_FTR_PMAO_BUG'),
    (0x0000080000000000, 'CPU_FTR_POWER9_DD2_1'),
    (0x0000100000000000, 'CPU_FTR_P9_TM_HV_ASSIST'),
    (0x0000200000000000, 'CPU_FTR_P9_TM_XER_SO_BUG'),
    (0x0000400000000000, 'CPU_FTR_P9_TLBIE_STQ_BUG'),
    (0x0000800000000000, 'CPU_FTR_P9_TIDR'),
    (0x0001000000000000, 'CPU_FTR_P9_TLBIE_ERAT_BUG'),
    (0x0002000000000000, 'CPU_FTR_P9_RADIX_PREFETCH_BUG'),
    (0x0004000000000000, 'CPU_FTR_ARCH_31'),
    (0x0008000000000000, 'CPU_FTR_DAWR1'),
]

def decode_ftr(features, value):
    s = []
    remainder = value
    for mask, name in features:
        if value & mask:
            s.append(name)
        remainder &= ~mask

    if remainder:
        s.append("UNKNOWN={:x}".format(remainder))

    return ', '.join(s)


def decode_cpu_ftr(value):
    return decode_ftr(cpu_features, value)

mmu_features = [
    (0x00000001, 'MMU_FTR_HPTE_TABLE'),
    (0x00000002, 'MMU_FTR_TYPE_8xx'),
    (0x00000004, 'MMU_FTR_TYPE_40x'),
    (0x00000008, 'MMU_FTR_TYPE_44x'),
    (0x00000010, 'MMU_FTR_TYPE_FSL_E'),
    (0x00000020, 'MMU_FTR_TYPE_47x'),
    (0x00000040, 'MMU_FTR_TYPE_RADIX'),
    (0x00000200, 'MMU_FTR_BOOK3S_KUAP'),
    (0x00000400, 'MMU_FTR_BOOK3S_KUEP'),
    (0x00000800, 'MMU_FTR_PKEY'),
    (0x00002000, 'MMU_FTR_68_BIT_VA'),
    (0x00004000, 'MMU_FTR_KERNEL_RO'),
    (0x00008000, 'MMU_FTR_TLBIE_CROP_VA'),
    (0x00010000, 'MMU_FTR_USE_HIGH_BATS'),
    (0x00020000, 'MMU_FTR_BIG_PHYS'),
    (0x00040000, 'MMU_FTR_USE_TLBIVAX_BCAST'),
    (0x00080000, 'MMU_FTR_USE_TLBILX'),
    (0x00100000, 'MMU_FTR_LOCK_BCAST_INVAL'),
    (0x00200000, 'MMU_FTR_NEED_DTLB_SW_LRU'),
    (0x00800000, 'MMU_FTR_USE_TLBRSRV'),
    (0x01000000, 'MMU_FTR_USE_PAIRED_MAS'),
    (0x02000000, 'MMU_FTR_NO_SLBIE_B'),
    (0x04000000, 'MMU_FTR_16M_PAGE'),
    (0x08000000, 'MMU_FTR_TLBIEL'),
    (0x10000000, 'MMU_FTR_LOCKLESS_TLBIE'),
    (0x20000000, 'MMU_FTR_CI_LARGE_PAGE'),
    (0x40000000, 'MMU_FTR_1T_SEGMENT'),
    (0x80000000, 'MMU_FTR_RADIX_KUAP'),
]


def decode_mmu_ftr(value):
    return decode_ftr(mmu_features, value)


fw_features = [
    (0x0000000000000001, 'FW_FEATURE_PFT'),
    (0x0000000000000002, 'FW_FEATURE_TCE'),
    (0x0000000000000004, 'FW_FEATURE_SPRG0'),
    (0x0000000000000008, 'FW_FEATURE_DABR'),
    (0x0000000000000010, 'FW_FEATURE_COPY'),
    (0x0000000000000020, 'FW_FEATURE_ASR'),
    (0x0000000000000040, 'FW_FEATURE_DEBUG'),
    (0x0000000000000080, 'FW_FEATURE_TERM'),
    (0x0000000000000100, 'FW_FEATURE_PERF'),
    (0x0000000000000200, 'FW_FEATURE_DUMP'),
    (0x0000000000000400, 'FW_FEATURE_INTERRUPT'),
    (0x0000000000000800, 'FW_FEATURE_MIGRATE'),
    (0x0000000000001000, 'FW_FEATURE_PERFMON'),
    (0x0000000000002000, 'FW_FEATURE_CRQ'),
    (0x0000000000004000, 'FW_FEATURE_VIO'),
    (0x0000000000008000, 'FW_FEATURE_RDMA'),
    (0x0000000000010000, 'FW_FEATURE_LLAN'),
    (0x0000000000020000, 'FW_FEATURE_BULK_REMOVE'),
    (0x0000000000040000, 'FW_FEATURE_XDABR'),
    (0x0000000000080000, 'FW_FEATURE_PUT_TCE_IND'),
    (0x0000000000100000, 'FW_FEATURE_SPLPAR'),
    (0x0000000000400000, 'FW_FEATURE_LPAR'),
    (0x0000000000800000, 'FW_FEATURE_PS3_LV1'),
    (0x0000000001000000, 'FW_FEATURE_HPT_RESIZE'),
    (0x0000000002000000, 'FW_FEATURE_CMO'),
    (0x0000000004000000, 'FW_FEATURE_VPHN'),
    (0x0000000008000000, 'FW_FEATURE_XCMO'),
    (0x0000000010000000, 'FW_FEATURE_OPAL'),
    (0x0000000040000000, 'FW_FEATURE_SET_MODE'),
    (0x0000000080000000, 'FW_FEATURE_BEST_ENERGY'),
    (0x0000000100000000, 'FW_FEATURE_TYPE1_AFFINITY'),
    (0x0000000200000000, 'FW_FEATURE_PRRN'),
    (0x0000000400000000, 'FW_FEATURE_DRMEM_V2'),
    (0x0000000800000000, 'FW_FEATURE_DRC_INFO'),
    (0x0000001000000000, 'FW_FEATURE_BLOCK_REMOVE'),
    (0x0000002000000000, 'FW_FEATURE_PAPR_SCM'),
    (0x0000004000000000, 'FW_FEATURE_ULTRAVISOR'),
    (0x0000008000000000, 'FW_FEATURE_STUFF_TCE'),
]


def decode_fw_ftr(value):
    return decode_ftr(fw_features, value)


def run_objdump(path, endian):
    if endian == 'little':
        flag = '-EL'
    else:
        flag = '-EB'

    cmd = f'ppc64le-objdump -b binary -m powerpc -D {flag} {path}'
    out = check_output(cmd.split(), stderr=subprocess.STDOUT).decode('utf-8')
    lines = out.splitlines()
    return lines[7:]


def objdump_range(bin_file, path, endian, start, end):
    if start == end:
        print("Warning: empty range {:x}".format(start))
        return []

    offset = find_section_by_addr(path, start, end)

    bin_file.seek(offset)
    data = bin_file.read(end - start)

    fd, temp_path = mkstemp()
    temp = os.fdopen(fd, 'wb')
    temp.write(data)
    temp.close()

    s = run_objdump(temp_path, endian)
    os.unlink(temp_path)
    return s


def dump_fixups(path, syms, section, decode_fn=None):
    bin_file = open(path, 'rb')
    endian = get_endian(path)

    for (entry_addr, mask, value, start, end, alt_start, alt_end) in iter_fixups(path, section):
        start_sym, start_offset = find_addr(syms, start)
        end_sym, end_offset = find_addr(syms, end)
        alt_start_sym, alt_start_offset = find_addr(syms, alt_start)
        alt_end_sym, alt_end_offset = find_addr(syms, alt_end)

        mask_features = ''
        value_features = ''
        VARIANT = ''
        if mask == 0 and value == 0:
            variant = '(never patched)'
        elif mask == 0 and value != 0:
            variant = '(always patched)'
        else:
            if mask == value:
                variant = "(if set)"
            elif value == 0:
                variant = "(if clear)"

            if decode_fn:
                mask_features = decode_fn(mask)
                value_features = decode_fn(value)

        print(f'{entry_addr:016x} mask {mask:016x} {mask_features} {variant}')
        print(f'                value {value:016x} {value_features}')
        print(f'                 from {start:016x} {start_sym}+0x{start_offset:x}')
        print(f'                   to {end:016x} {end_sym}+0x{end_offset:x}')

        for line in objdump_range(bin_file, path, endian, start, end):
            print(f'                   {line}')

        if alt_end - alt_start > 0:
            print(f'            alt_start {alt_start:016x} {alt_start_sym}+0x{alt_start_offset:x}')
            print(f'              alt_end {alt_end:016x} {alt_end_sym}+0x{alt_end_offset:x}')

            for line in objdump_range(bin_file, path, endian, alt_start, alt_end):
                print(f'                   {line}')

        print()



def main(args):
    if len(args) == 0:
        print("Usage: %s <vmlinux>" % sys.argv[0], file=sys.stderr)
        return 1

    path = args[0]
    syms = read_symbols(path)

    print("# Dumping CPU feature fixup entries")
    dump_fixups(path, syms, '__ftr_fixup', decode_cpu_ftr)

    print("# Dumping MMU feature fixup entries")
    dump_fixups(path, syms, '__mmu_ftr_fixup', decode_mmu_ftr)

    print("# Dumping Firmware feature fixup entries")
    dump_fixups(path, syms, '__fw_ftr_fixup', decode_fw_ftr)

    return 0


try:
    sys.exit(main(sys.argv[1:]))
except (KeyboardInterrupt, BrokenPipeError):
    pass
