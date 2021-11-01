import os
import sys
import logging
from utils import get_env_var, get_endian
from pexpect_utils import PexpectHelper


def get_qemu(name='qemu-system-ppc64'):
    qemu = get_env_var(name.upper().replace('-', '_'))
    if qemu is None:
        # Defer to $PATH search
        qemu = name

    logging.debug(f'Using qemu {qemu} for {name}')
    return qemu


def get_root_disk_path():
    path = get_env_var('ROOT_DISK_PATH', None)
    if path is not None:
        return path

    base = os.path.dirname(sys.argv[0])
    # Assumes we're called from scripts/boot/qemu-xxx
    path = f'{base}/../../root-disks'
    if os.path.isdir(path):
        return path

    return ''


def get_root_disk(fname):
    val = os.path.join(get_root_disk_path(), fname)
    logging.debug(f'Using rootfs {val}')
    return val


def get_qemu_version(emulator):
    p = PexpectHelper()
    p.spawn('%s --version' % emulator)
    p.expect('QEMU emulator version ([0-9]+)\.([0-9]+)')
    major, minor = p.matches()
    return (int(major), int(minor))


def qemu_command(qemu='qemu-system-ppc64', machine='pseries,cap-htm=off', cpu=None,
                 mem='1G', smp=1, vmlinux=None, initrd=None, drive=None,
                 cmdline='', accel='tcg', net='-nic user'):

    qemu_path = get_qemu(qemu)
    logging.info('Using qemu version %s.%s' % get_qemu_version(qemu_path))

    if vmlinux is None:
        vmlinux = get_vmlinux()

    l = [
        get_qemu(qemu),
        '-nographic',
        '-vga', 'none',
        '-M', machine,
        '-smp', str(smp),
        '-m', mem,
        '-accel', accel,
        '-kernel', vmlinux,
        net,
    ]

    if initrd is None and drive is None:
        if qemu == 'qemu-system-ppc':
            subarch = 'ppc'
        elif get_endian(vmlinux) == 'little':
            subarch = 'ppc64le'
        else:
            subarch = 'ppc64'

        initrd = f'{subarch}-rootfs.cpio.gz'

    if initrd:
        l.append('-initrd')
        l.append(get_root_disk(initrd))

    if drive:
        l.append(drive)

    if cpu is not None:
        l.append('-cpu')
        l.append(cpu)

    if len(cmdline):
        l.append('-append')
        l.append(f'"{cmdline}"')

    logging.debug(l)

    return ' '.join(l)


def qemu_net_setup(p, iface='eth0'):
    p.cmd('ip addr show')
    p.cmd('ls -l /sys/class/net')
    p.cmd(f'ip addr add dev {iface} 10.0.2.15/24')
    p.cmd(f'ip link set {iface} up')
    p.cmd('ip addr show')
    p.cmd('route add default gw 10.0.2.2')
    p.cmd('route -n')
