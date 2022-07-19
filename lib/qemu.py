import atexit
import os
import sys
import subprocess
import logging
from utils import *
from pexpect_utils import PexpectHelper, standard_boot, ping_test, wget_test


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
                 host_mount=None, cmdline='', accel='tcg', net='-nic user', gdb=None,
                 extra_args=[]):

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

    if host_mount:
        bus = ''
        if 'powernv' in machine:
            bus = ',bus=pcie.0'

        l.append(f'-fsdev local,id=fsdev0,path={host_mount},security_model=none')
        l.append(f'-device virtio-9p-pci,fsdev=fsdev0,mount_tag=host{bus}')

    if cpu is not None:
        l.append('-cpu')
        l.append(cpu)

    if len(cmdline):
        l.append('-append')
        l.append(f'"{cmdline}"')

    if gdb:
        l.append(gdb)

    l.extend(extra_args)

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


def qemu_main(qemu_machine, cpuinfo_platform, cpu, net, args):
    expected_release = get_expected_release()
    if expected_release is None:
        return False

    vmlinux = get_vmlinux()
    if vmlinux is None:
        return False

    accel = get_env_var('ACCEL', 'tcg')

    smp = get_env_var('SMP', None)
    if smp is None:
        if accel == 'tcg':
            smp = 2
        else:
            smp = 8

    cmdline = 'noreboot '

    cloud_image = os.environ.get('CLOUD_IMAGE', False)
    if cloud_image:
        # Create snapshot image
        rdpath = get_root_disk_path()
        src = f'{rdpath}/{cloud_image}'
        pid = os.getpid()
        dst = f'{rdpath}/qemu-temp-{pid}.img'
        cmd = f'qemu-img create -f qcow2 -F qcow2 -b {src} {dst}'.split()
        subprocess.run(cmd, check=True)

        atexit.register(lambda: os.unlink(dst))

        if 'ubuntu' in cloud_image:
            cmdline += 'root=/dev/vda1 '
            prompt = 'root@ubuntu:~#'
        else:
            cmdline += 'root=/dev/vda2 '
            prompt = '\[root@fedora ~\]#'

        if 'powernv' in qemu_machine:
            interface = 'none'
            drive = '-device virtio-blk-pci,drive=drive0,id=blk0,bus=pcie.0 ' \
                    '-device virtio-blk-pci,drive=drive1,id=blk1,bus=pcie.1 '
        else:
            interface = 'virtio'
            drive = ''

        drive += f'-drive file={dst},format=qcow2,if={interface},id=drive0 ' \
                 f'-drive file={rdpath}/cloud-init-user-data.img,format=raw,if={interface},readonly=on,id=drive1'
    else:
        drive = None

    extra_args = []
    if 'pseries' in qemu_machine:
        if accel == 'kvm':
            extra_args = ['-device spapr-rng,use-kvm=true']
        else:
            extra_args = ['-device spapr-rng,rng=rng0 -object rng-random,filename=/dev/urandom,id=rng0']

    host_mount = os.environ.get('QEMU_HOST_MOUNT', '')
    if host_mount and not os.path.isdir(host_mount):
        logging.error('QEMU_HOST_MOUNT must point to a directory')
        return False

    cmdline += get_env_var('LINUX_CMDLINE', '')

    # Default timeout for a single pexpect call
    pexpect_timeout = int(get_env_var('QEMU_PEXPECT_TIMEOUT', 60))

    gdb = None
    if '--gdb' in args:
        gdb = '-s -S'
        pexpect_timeout = 0

    cmd = qemu_command(machine=qemu_machine, cpu=cpu, mem='4G', smp=smp, vmlinux=vmlinux,
                       drive=drive, host_mount=host_mount, cmdline=cmdline, accel=accel,
                       net=net, gdb=gdb, extra_args=extra_args)

    if '--interactive' in args:
        logging.info("Running interactively ...")
        rc = subprocess.run(cmd, shell=True).returncode
        return rc == 0

    setup_timeout(10 * pexpect_timeout)
    boot_timeout = pexpect_timeout * 5

    logpath = get_env_var('QEMU_CONSOLE_LOG', 'console.log')

    p = PexpectHelper()
    p.spawn(cmd, logfile=open(logpath, 'w'), timeout=pexpect_timeout)

    if cloud_image:
        standard_boot(p, prompt=prompt, login=True, password='linuxppc', timeout=boot_timeout)
    else:
        standard_boot(p, timeout=boot_timeout)

    p.send("echo -n 'booted-revision: '; uname -r")
    p.expect(f'booted-revision: {expected_release}')
    p.expect_prompt()

    p.send('cat /proc/cpuinfo')
    p.expect(cpuinfo_platform)
    p.expect_prompt()

    if os.environ.get('QEMU_NET_TESTS', True) != '0':
        qemu_net_setup(p)
        ping_test(p)
        wget_test(p)

    if host_mount:
        # Clear timeout, we don't know how long it will take
        setup_timeout(0)
        p.cmd('mkdir -p /mnt')
        p.cmd('mount -t 9p -o version=9p2000.L,trans=virtio host /mnt')
        host_command = os.environ.get('QEMU_HOST_COMMAND', 'run')
        p.send(f'[ -x /mnt/{host_command} ] && (cd /mnt && ./{host_command})')
        p.expect_prompt(timeout=None) # no timeout

    p.send('halt')
    p.wait_for_exit(timeout=boot_timeout)

    if filter_log_warnings(open(logpath), open('warnings.txt', 'w')):
        logging.error('Errors/warnings seen in console log')
        return False

    logging.info('Test completed OK')

    return True
