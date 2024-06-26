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
        self.use_vof = False
        self.smp = None
        self.cloud_image = None
        self.host_mounts = []
        self.cmdline = ['noreboot']
        self.pexpect_timeout = 60
        self.logpath = 'console.log'
        self.quiet = False
        self.net = None
        self.net_tests = False
        self.host_command = 'run'
        self.gdb = None
        self.interactive = False
        self.drives = []
        self.next_drive = 0
        self.initrd = None
        self.compat_rootfs = False
        self.boot_func = None
        self.shutdown = None
        self.callback = None
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
        self.use_vof = get_env_var('QEMU_VOF', self.use_vof)
        self.cpu = get_env_var('CPU', self.cpu)
        self.smp = get_env_var('SMP', self.smp)
        self.mem = get_env_var('QEMU_MEM_SIZE', self.mem)
        self.initrd = get_env_var('QEMU_INITRD', self.initrd)
        self.cloud_image = get_env_var('CLOUD_IMAGE', self.cloud_image)
        self.compat_rootfs = get_env_var('COMPAT_USERSPACE', self.compat_rootfs)
        self.pexpect_timeout = int(get_env_var('QEMU_PEXPECT_TIMEOUT', self.pexpect_timeout))
        self.logpath = get_env_var('QEMU_CONSOLE_LOG', self.logpath)
        self.quiet = get_env_var('QEMU_QUIET', self.quiet)
        self.net_tests = get_env_var('QEMU_NET_TESTS', self.net_tests) == '1'
        self.host_command = get_env_var('QEMU_HOST_COMMAND', self.host_command)
        self.expected_release = get_expected_release()
        self.vmlinux = get_vmlinux()
        self.cpuinfo = None
        val = get_env_var('LINUX_CMDLINE', None)
        if val:
            self.cmdline.append(val)

        val = get_env_var('QEMU_HOST_MOUNTS', None)
        if val:
            self.host_mounts.extend(val.split(':'))


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
            else:
                self.__set_spectre_v2_caps()

            if self.cpu and self.accel == 'kvm':
                if self.cpu != 'host':
                    self.machine_caps += ['max-cpu-compat=%s' % self.cpu.lower()]
                self.cpu = None

            if self.use_vof:
                self.machine_caps += ['x-vof=on']

        if self.cpuinfo is None:
            if self.machine_is('pseries'):
                self.cpuinfo = [r'IBM pSeries \(emulated by qemu\)']
            elif self.machine_is('powernv'):
                self.cpuinfo = [r'IBM PowerNV \(emulated by qemu\)']
            elif self.machine == 'mac99':
                self.cpuinfo = [r'PowerMac3,1 MacRISC MacRISC2 Power Macintosh']
            elif self.machine == 'g3beige':
                self.cpuinfo = [r'AAPL,PowerMac G3 MacRISC']
            elif self.machine == 'bamboo':
                self.cpuinfo = [r'PowerPC 44x Platform']
            elif self.machine == 'ppce500':
                self.cpuinfo = [r'QEMU ppce500']
                if self.cpu:
                    self.cpuinfo.insert(0, f'cpu\\s+: {self.cpu}')

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
                self.prompt = 'root@ubuntu:~#'
            elif 'fedora' in self.cloud_image:
                self.prompt = r'\[root@fedora ~\]#'
            elif 'debian' in self.cloud_image:
                self.prompt = 'root@debian:~#'

        if self.prompt is None:
            # Default prompt for our root disks
            self.prompt = "/ #"

        if self.initrd is None and len(self.drives) == 0 and self.cloud_image is None:
            if self.compat_rootfs or self.qemu_path.endswith('qemu-system-ppc'):
                subarch = 'ppc'
            elif get_endian(self.vmlinux) == 'little':
                subarch = 'ppc64le'
            elif self.machine_is('powernv') or self.machine_is('pseries'):
                subarch = 'ppc64'
            else:
                subarch = 'ppc64-novsx'

            self.initrd = f'{subarch}-rootfs.cpio.gz'

        if self.host_mounts:
            i = 0
            for path in self.host_mounts:
                if self.machine_is('powernv'):
                    bus = f',bus=pcie.{i+2}'
                else:
                    bus = ''

                self.extra_args.append(f'-fsdev local,id=fsdev{i},path={path},security_model=none')
                self.extra_args.append(f'-device virtio-9p-pci,fsdev=fsdev{i},mount_tag=host{i}{bus}')
                i += 1

        if self.machine_is('pseries'):
            rng = '-object rng-random,filename=/dev/urandom,id=rng0 -device spapr-rng,rng=rng0'
            if self.accel == 'kvm':
                rng += ',use-kvm=true'

            self.extra_args += [rng]

        if self.boot_func is None:
            def boot(p, timeout, qconf):
                standard_boot(p, qconf.login, qconf.user, qconf.password, timeout)

            self.boot_func = boot

    def add_drive(self, args):
        drive_id = self.next_drive
        self.next_drive += 1

        if self.machine_is('powernv'):
            interface = 'none'
            self.drives.append(f'-device virtio-blk-pci,drive=drive{drive_id},id=blk{drive_id},bus=pcie.{drive_id}')
        else:
            interface = 'virtio'

        self.drives.append(f'-drive {args},if={interface},id=drive{drive_id}')

        # Convert to drive letter
        return chr(ord('a') + drive_id)
        
    def prepare_cloud_image(self):
        if self.cloud_image is None:
            return

        rdpath = get_root_disk_path()
        img_path = f'{rdpath}/{self.cloud_image}'

        if self.cloud_image.endswith('.qcow2'):
            # Create snapshot image
            pid = os.getpid()
            dst = f'{rdpath}/qemu-temp-{pid}.img'
            cmd = f'qemu-img create -f qcow2 -F qcow2 -b {img_path} {dst}'.split()
            subprocess.run(cmd, check=True)
            atexit.register(lambda: os.unlink(dst))
            img_path = dst
            format = 'qcow2'
        else:
            format = 'raw'

        cloud_drive = self.add_drive(f'file={img_path},format={format}')
        self.add_drive(f'file={rdpath}/cloud-init-user-data.img,format=raw,readonly=on')
        
        if 'ubuntu' in self.cloud_image:
            self.cmdline.insert(0, f'root=/dev/vd{cloud_drive}1')
        elif 'fedora34' in self.cloud_image or 'debian' in self.cloud_image:
            self.cmdline.insert(0, f'root=/dev/vd{cloud_drive}2')
        elif 'fedora' in self.cloud_image:
            self.cmdline.insert(0, 'systemd.mask=hcn-init.service systemd.hostname=fedora')
            self.cmdline.insert(0, f'root=/dev/vd{cloud_drive}5 rootfstype=btrfs rootflags=subvol=root')

    def __set_spectre_v2_caps(self):
        try:
            body = open('/sys/devices/system/cpu/vulnerabilities/spectre_v2', 'r').read()
        except (FileNotFoundError, PermissionError):
            # Should be readable, but continue anyway and cross fingers
            return

        for s in ['Indirect branch cache disabled', 'Software count cache flush']:
            if s in body:
                return

        self.machine_caps += ['cap-ccf-assist=off']

    def cmd(self):
        logging.info('Using qemu version %s.%s "%s"' % get_qemu_version(self.qemu_path))

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

        if len(self.drives):
            l.extend(self.drives)

        if self.cpu is not None:
            l.append('-cpu')
            l.append(self.cpu)

        if len(self.cmdline):
            l.append('-append')
            cmdline = ' '.join(self.cmdline)
            l.append(f'"{cmdline}"')

        l.extend(self.extra_args)

        logging.debug(l)

        return ' '.join(l)


def qemu_monitor_shutdown(p):
    p.send('\x01c') # invoke qemu monitor
    p.expect(r'\(qemu\)')
    p.send('quit')


def get_qemu(name='qemu-system-ppc64'):
    # This looks for QEMU_SYSTEM_PPC64 or QEMU_SYSTEM_PPC in the environment
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
    p.spawn('%s --version' % emulator, quiet=True)
    p.expect(r'QEMU emulator version (([0-9]+)\.([0-9]+)[^\n]*)')
    full, major, minor = p.matches()
    return (int(major), int(minor), full.strip())


def qemu_supports_p10(path):
    major, _, _ = get_qemu_version(path)
    return major >= 7


def get_host_cpu():
    f = open('/proc/cpuinfo')
    while True:
        # Not pretty but works
        l = f.readline()
        words = l.split()
        if words[0] == 'cpu':
            return words[2]


def kvm_possible(machine, cpu):
    if machine == 'pseries' and os.path.exists('/sys/module/kvm_hv'):
        host_cpu = get_host_cpu()
        if host_cpu == 'POWER8':
            supported = ['POWER8']
        elif host_cpu == 'POWER9':
            supported = ['POWER8', 'POWER9']
        elif host_cpu == 'POWER10':
            supported = ['POWER8', 'POWER9', 'POWER10']
        else:
            supported = []

        return cpu in supported

    return False


def kvm_or_tcg(machine, cpu):
    if kvm_possible(machine, cpu):
        return 'kvm'
    return 'tcg'


def qemu_net_setup(p):
    p.cmd('ip addr show')
    p.cmd('ls -l /sys/class/net')
    p.cmd('iface=$(ls -1d /sys/class/net/e* | head -1 | cut -d/ -f 5)')
    p.cmd('ip addr add dev $iface 10.0.2.15/24')
    p.cmd('ip link set $iface up')
    p.cmd('ip addr show')
    p.cmd('ip route show')


def qemu_main(qconf):
    if qconf.expected_release is None or qconf.vmlinux is None:
        return False

    for path in qconf.host_mounts:
        if not os.path.isdir(path):
            logging.error(f"QEMU_HOST_MOUNTS must point to directories. Not found: '{path}'")
            return False

    qconf.prepare_cloud_image()

    cmd = qconf.cmd()

    logging.info(f"Running '{cmd}'")

    if qconf.interactive:
        logging.info("Running interactively ...")
        if qconf.host_mounts:
            logging.info("To mount host mount points run:")
            logging.info(" mkdir -p /mnt; mount -t 9p -o version=9p2000.L,trans=virtio host0 /mnt")

        rc = subprocess.run(cmd, shell=True).returncode
        return rc == 0

    setup_timeout(10 * qconf.pexpect_timeout)
    pexpect_timeout = qconf.pexpect_timeout
    if pexpect_timeout:
        boot_timeout = pexpect_timeout * 5
    else:
        boot_timeout = pexpect_timeout = None

    p = PexpectHelper()
    p.spawn(cmd, logfile=open(qconf.logpath, 'w'), timeout=pexpect_timeout, quiet=qconf.quiet)

    p.push_prompt(qconf.prompt)
    qconf.boot_func(p, boot_timeout, qconf)

    p.send('echo "booted-revision: `uname -r`"')
    p.expect(f'booted-revision: {qconf.expected_release}')
    p.expect_prompt()

    p.send('cat /proc/cpuinfo')
    if qconf.cpuinfo:
        for s in qconf.cpuinfo:
            p.expect(s)
    p.expect_prompt()

    if qconf.net_tests:
        qemu_net_setup(p)
        ping_test(p)

    if qconf.host_mounts:
        # Clear timeout, we don't know how long it will take
        setup_timeout(0)

        for i in range(0, len(qconf.host_mounts)):
            p.cmd(f'mkdir -p /mnt/host{i}')
            p.cmd(f'mount -t 9p -o version=9p2000.L,trans=virtio host{i} /mnt/host{i}')

        for i in range(0, len(qconf.host_mounts)):
            p.send(f'[ -x /mnt/host{i}/{qconf.host_command} ] && (cd /mnt/host{i} && ./{qconf.host_command})')
            p.expect_prompt(timeout=None) # no timeout

    if qconf.callback and qconf.callback(p) is False:
        logging.error("Callback failed")
        return False

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
