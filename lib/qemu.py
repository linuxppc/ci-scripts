import atexit
import os
import sys
import subprocess
import logging
from utils import *
from pexpect_utils import PexpectHelper, standard_boot, ping_test, wget_test


class QemuConfig:
    def __init__(self, machine):
        self.machine = machine
        self.machine_caps = []
        self.cpu = None
        self.mem = None
        self.accel = 'tcg'
        self.smp = None
        self.cloud_image = None
        self.host_mount = None
        self.cmdline = 'noreboot '
        self.pexpect_timeout = 60
        self.logpath = 'console.log'
        self.net = None
        self.net_tests = True
        self.host_command = 'run'
        self.gdb = None
        self.interactive = False
        self.drive = None
        self.initrd = None
        self.compat_rootfs = False
        self.shutdown = None
        self.extra_args = []
        self.qemu_path = None
        self.login = False
        self.prompt = None
        self.user = 'root'
        self.password = None

    def machine_is(self, needle):
        return self.machine.startswith(needle)

    def configure_from_env(self):
        self.accel = get_env_var('ACCEL', self.accel)
        self.cpu = get_env_var('CPU', self.cpu)
        self.smp = get_env_var('SMP', self.smp)
        self.mem = get_env_var('QEMU_MEM_SIZE', self.mem)
        self.initrd = get_env_var('QEMU_INITRD', self.initrd)
        self.cloud_image = get_env_var('CLOUD_IMAGE', self.cloud_image)
        self.host_mount = get_env_var('QEMU_HOST_MOUNT', self.host_mount)
        self.compat_rootfs = get_env_var('COMPAT_USERSPACE', self.compat_rootfs)
        self.cmdline += get_env_var('LINUX_CMDLINE', '') + ' '
        self.pexpect_timeout = int(get_env_var('QEMU_PEXPECT_TIMEOUT', self.pexpect_timeout))
        self.logpath = get_env_var('QEMU_CONSOLE_LOG', self.logpath)
        self.net_tests = get_env_var('QEMU_NET_TESTS', self.net_tests) != '0'
        self.host_command = get_env_var('QEMU_HOST_COMMAND', self.host_command)
        self.expected_release = get_expected_release()
        self.vmlinux = get_vmlinux()
        self.cpuinfo = None

    def configure_from_args(self, args):
        if '--gdb' in args:
            self.extra_args += ['-S', '-s']
            self.pexpect_timeout = 0

        if '--interactive' in args:
            self.interactive = True

    def apply_defaults(self):
        if self.machine_is('pseries'):
            if self.accel == 'tcg':
                self.machine_caps += ['cap-htm=off']

            if self.cpu and self.accel == 'kvm':
                if self.cpu != 'host':
                    self.machine_caps += ['max-cpu-compat=%s' % self.cpu.lower()]
                self.cpu = None

        if self.cpuinfo is None:
            if self.machine_is('pseries'):
                self.cpuinfo = 'IBM pSeries \(emulated by qemu\)'
            elif self.machine_is('powernv'):
                self.cpuinfo = 'IBM PowerNV \(emulated by qemu\)'
            elif self.machine == 'mac99':
                self.cpuinfo = 'PowerMac3,1 MacRISC MacRISC2 Power Macintosh'
            elif self.machine == 'g3beige':
                self.cpuinfo = 'AAPL,PowerMac G3 MacRISC'
            elif self.machine == 'bamboo':
                self.cpuinfo = 'PowerPC 44x Platform'
            elif self.machine == 'ppce500':
                self.cpuinfo = 'QEMU ppce500'

        if self.qemu_path is None:
            if self.machine_is('pseries') or self.machine_is('powernv'):
                self.qemu_path = 'qemu-system-ppc64'
            else:
                self.qemu_path = 'qemu-system-ppc'

        self.qemu_path = get_qemu(self.qemu_path)

        if self.mem is None:
            if self.machine_is('pseries') or self.machine_is('powernv'):
                self.mem = '4G'
            else:
                self.mem = '1G'

        if self.smp is None:
            if self.machine_is('mac99'): # Doesn't support SMP
                self.smp = 1
            elif self.accel == 'tcg':
                self.smp = 2
            else:
                self.smp = 8

        if self.net is None:
            if self.machine_is('pseries'):
                self.net = '-nic user,model=virtio-net-pci'
            elif self.machine_is('powernv'):
                self.net = '-netdev user,id=net0 -device e1000e,netdev=net0'
            else:
                self.net = '-nic user'

        if self.machine == 'powernv':
            if self.cpu and self.cpu.upper() == 'POWER8':
                self.machine = 'powernv8'
            elif self.cpu and self.cpu.upper() == 'POWER10':
                self.machine = 'powernv10'
            else:
                self.machine = 'powernv9'

        if self.cloud_image:
            self.login = True
            self.password = 'linuxppc'
            self.user = 'root'

            if 'ubuntu' in self.cloud_image:
                self.cmdline += 'root=/dev/vda1 '
                self.prompt = 'root@ubuntu:~#'
            else:
                self.cmdline += 'root=/dev/vda2 '
                self.prompt = '\[root@fedora ~\]#'

        if self.initrd is None and self.drive is None and self.cloud_image is None:
            if self.compat_rootfs or self.qemu_path.endswith('qemu-system-ppc'):
                subarch = 'ppc'
            elif get_endian(self.vmlinux) == 'little':
                subarch = 'ppc64le'
            elif self.machine_is('powernv') or self.machine_is('pseries'):
                subarch = 'ppc64'
            else:
                subarch = 'ppc64-novsx'

            self.initrd = f'{subarch}-rootfs.cpio.gz'

        if self.host_mount:
            bus = ''
            if self.machine_is('powernv'):
                bus = ',bus=pcie.0'

            self.extra_args.append(f'-fsdev local,id=fsdev0,path={self.host_mount},security_model=none')
            self.extra_args.append(f'-device virtio-9p-pci,fsdev=fsdev0,mount_tag=host{bus}')

        if self.machine_is('pseries'):
            rng = '-object rng-random,filename=/dev/urandom,id=rng0 -device spapr-rng,rng=rng0'
            if self.accel == 'kvm':
                rng += ',use-kvm=true'

            self.extra_args += [rng]


    def cmd(self):
        logging.info('Using qemu version %s.%s' % get_qemu_version(self.qemu_path))

        machine = self.machine
        if len(self.machine_caps):
            machine = ','.join([machine] + self.machine_caps)

        l = [
            self.qemu_path,
            '-nographic',
            '-vga', 'none',
            '-M', machine,
            '-smp', str(self.smp),
            '-m', self.mem,
            '-accel', self.accel,
            '-kernel', self.vmlinux,
        ]

        if self.net:
            l.append(self.net)

        if self.initrd:
            l.append('-initrd')
            l.append(get_root_disk(self.initrd))

        if self.drive:
            l.append(self.drive)

        if self.cpu is not None:
            l.append('-cpu')
            l.append(self.cpu)

        if len(self.cmdline):
            l.append('-append')
            l.append(f'"{self.cmdline}"')

        l.extend(self.extra_args)

        logging.debug(l)

        return ' '.join(l)


def qemu_monitor_shutdown(p):
    p.send('\x01c') # invoke qemu monitor
    p.expect('\(qemu\)')
    p.send('quit')


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


def qemu_net_setup(p, iface='eth0'):
    p.cmd('ip addr show')
    p.cmd('ls -l /sys/class/net')
    p.cmd(f'ip addr add dev {iface} 10.0.2.15/24')
    p.cmd(f'ip link set {iface} up')
    p.cmd('ip addr show')
    p.cmd('route add default gw 10.0.2.2')
    p.cmd('route -n')


def qemu_main(qconf):
    if qconf.expected_release is None or qconf.vmlinux is None:
        return False

    if qconf.host_mount and not os.path.isdir(qconf.host_mount):
        logging.error('QEMU_HOST_MOUNT must point to a directory')
        return False

    if qconf.cloud_image:
        # Create snapshot image
        rdpath = get_root_disk_path()
        src = f'{rdpath}/{qconf.cloud_image}'
        pid = os.getpid()
        dst = f'{rdpath}/qemu-temp-{pid}.img'
        cmd = f'qemu-img create -f qcow2 -F qcow2 -b {src} {dst}'.split()
        subprocess.run(cmd, check=True)
        atexit.register(lambda: os.unlink(dst))

        if qconf.machine_is('powernv'):
            interface = 'none'
            qconf.extra_args.append('-device virtio-blk-pci,drive=drive0,id=blk0,bus=pcie.0')
            qconf.extra_args.append('-device virtio-blk-pci,drive=drive1,id=blk1,bus=pcie.1')
        else:
            interface = 'virtio'

        qconf.drive =  f'-drive file={dst},format=qcow2,if={interface},id=drive0 '
        qconf.drive += f'-drive file={rdpath}/cloud-init-user-data.img,format=raw,if={interface},readonly=on,id=drive1'

    cmd = qconf.cmd()

    logging.info(f"Running '{cmd}'")

    if qconf.interactive:
        logging.info("Running interactively ...")
        if qconf.host_mount:
            logging.info("To mount the host mount point run:")
            logging.info(" mkdir -p /mnt; mount -t 9p -o version=9p2000.L,trans=virtio host /mnt")

        rc = subprocess.run(cmd, shell=True).returncode
        return rc == 0

    setup_timeout(10 * qconf.pexpect_timeout)
    pexpect_timeout = qconf.pexpect_timeout
    if pexpect_timeout:
        boot_timeout = pexpect_timeout * 5
    else:
        boot_timeout = pexpect_timeout = None

    p = PexpectHelper()
    p.spawn(cmd, logfile=open(qconf.logpath, 'w'), timeout=pexpect_timeout)

    standard_boot(p, qconf.login, qconf.user, qconf.password, boot_timeout, qconf.prompt)

    p.send('echo "booted-revision: `uname -r`"')
    p.expect(f'booted-revision: {qconf.expected_release}')
    p.expect_prompt()

    p.send('cat /proc/cpuinfo')
    if qconf.cpuinfo:
        p.expect(qconf.cpuinfo)
    p.expect_prompt()

    if qconf.net_tests:
        qemu_net_setup(p)
        ping_test(p)
        wget_test(p)

    if qconf.host_mount:
        # Clear timeout, we don't know how long it will take
        setup_timeout(0)
        p.cmd('mkdir -p /mnt')
        p.cmd('mount -t 9p -o version=9p2000.L,trans=virtio host /mnt')
        p.send(f'[ -x /mnt/{qconf.host_command} ] && (cd /mnt && ./{qconf.host_command})')
        p.expect_prompt(timeout=None) # no timeout

    if qconf.shutdown:
        qconf.shutdown(p)
    else:
        p.send('poweroff')

    p.wait_for_exit(timeout=boot_timeout)

    if filter_log_warnings(open(qconf.logpath), open('warnings.txt', 'w')):
        logging.error('Errors/warnings seen in console log')
        return False

    logging.info('Test completed OK')

    return True
