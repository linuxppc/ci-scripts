from utils import check_env_vars, filter_log_warnings, setup_logging
from datetime import datetime, timedelta
from pexpect_utils import PexpectHelper
from subprocess import run
import argparse
import atexit
import logging
import pexpect
import time
import re
import os


def minutes(n):
    return n * 60


def run_ssh(args, timeout, input=None, stdout=None, capture_output=False):
    cmd = ['ssh',
           '-o', 'PasswordAuthentication=no',
           '-o', 'StrictHostKeyChecking=accept-new',
           '-o', 'ConnectTimeout=30',
           '-o', 'ServerAliveInterval=60'
    ]
    cmd.extend(args)

    logging.debug("Running %s", cmd)

    p = run(cmd, input=input, stdout=stdout, capture_output=capture_output, timeout=timeout)

    result = p.returncode == 0

    if capture_output:
        return (result, p.stdout)

    return result


def run_ssh_cmd(target, command, stdout=None, capture_output=False, timeout=None):
    if timeout is None:
        timeout = minutes(5)

    args = [target, command]
    return run_ssh(args, timeout, stdout=stdout, capture_output=capture_output)


def run_ssh_script(target, script, timeout, stdout=None, capture_output=False):
    args = ['-T', target]
    return run_ssh(args, timeout, script, stdout, capture_output)



def reboot_host(hostname):
    logging.info("Rebooting via SSH, current uptime/uname:")
    if not run_ssh_cmd(hostname, "uptime; uname -a; echo h > /proc/sysrq-trigger"):
        logging.error(f"Couldn't contact {hostname} to reboot it")
        return False

    if not run_ssh_cmd(hostname, "echo reboot | at now"):
        # Check we can still do a simple SSH
        if not run_ssh_cmd(hostname, "uname"):
            logging.error(f"Failed on 2nd attempt contacting {hostname} to reboot it")
            return False

        # Try sysrq
        cmd = "echo s > /proc/sysrq-trigger; echo u > /proc/sysrq-trigger; echo b > /proc/sysrq-trigger"
        if not run_ssh_cmd(hostname, cmd):
            logging.error(f"Failed using sysrq to reboot {hostname}.")
            return False

    logging.info(f"Requested {hostname} to reboot.")

    return True


def get_dmesg_via_ssh(hostname, dest=None):
    if dest is None:
        dest = 'dmesg.txt'

    f = open(dest, 'w')
    rc = run_ssh_cmd(hostname, "dmesg -S 2> /dev/null || dmesg", stdout=f)
    f.close()

    return rc


def wait_for_ssh(hostname, wait_secs, num_waits):
    wait_end = datetime.now() + timedelta(seconds=(wait_secs * num_waits))

    logging.info(f"Waiting {wait_secs}s up to {num_waits} times for SSH ...")

    for i in range(0, num_waits):
        if run_ssh_cmd(hostname, 'uptime', timeout=minutes(1)):
            return True

        if i > 0 and datetime.now() > wait_end:
            logging.info(f"Exceeded total wait time after {i} iterations.")
            break

        logging.info("No response from SSH, waiting ...")
        time.sleep(wait_secs)

    logging.error("Machine didn't respond to SSH!")
    return False


def check_kernel_release(hostname, expected):
    rc, output = run_ssh_cmd(hostname, 'uname -r', capture_output=True, timeout=minutes(1))
    if not rc:
        return rc

    actual = output.decode('utf-8').strip()
    return compare_uname_release(actual, expected)


def compare_uname_release(actual, expected):
    if actual != expected:
        logging.error(" Error: system booted wrong kernel?!")
        logging.error(f" Expected: '{expected}'")
        logging.error(f" Actual:   '{actual}'")
        return False

    logging.info(f"Got release: {actual}")

    return True


def check_uptime(hostname, threshold=300):
    rc, output = run_ssh_cmd(hostname, 'cat /proc/uptime', capture_output=True, timeout=minutes(1))
    if not rc:
        return False

    actual = output.decode('utf-8').strip().split('.')[0]
    try:
        actual = int(actual)
    except ValueError:
        logging.error(f"Couldn't parse uptime {actual}")
        return False

    if actual <= threshold:
        logging.info(f"Uptime {actual} seconds <= threshold {threshold}")
        return True
    else:
        logging.error(f"Uptime {actual} seconds > threshold {threshold}, reboot probably failed?")
        return False


# For machines that have no console or power control
class NoXcat:
    def __init__(self):
        pass

    def log_console(self):
        pass

    def close_console(self):
        pass

    def get_power_state(self):
        pass

    def set_power_state(self, action):
        pass


class OzXcat:
    def __init__(self, xcat_name, use_pdu=False):
        self.xcat_name = xcat_name
        self.use_pdu = use_pdu

    def log_console(self):
        self.console = p = PexpectHelper()
        p.bug_patterns = []
        p.spawn(f'ssh -t xcat-b /opt/xcat/bin/rcons {self.xcat_name} -f', timeout=30, quiet=True)
        p.log_to(open('console.log', 'w'))
        atexit.register(lambda: p.drain_and_terminate())

    def close_console(self):
        self.console.drain_and_terminate()

    def get_power_state(self):
        if self.use_pdu:
            action = 'pdustat'
        else:
            action = 'stat'

        logging.debug(f'Checking power state for {self.xcat_name}')
        p = run(['ssh',  'xcat-b', '/opt/xcat/bin/rpower', self.xcat_name, action], capture_output=True)

        if p.returncode != 0:
            return None

        output = p.stdout.decode('utf-8')

        if action == 'pdustat':
            pattern = re.compile(f'{self.xcat_name}: PDU.*\\) is (on|off)')
            match = pattern.match(output)
            if match:
                return match.group(1)

        # Result should be 'hostname: <something>'
        result = output.split(':', 1)[1].strip()

        # Translate HMC status
        if result == 'Running':
            result = 'on'
        elif result == 'Not Activated':
            result = 'off'

        return result

    def set_power_state(self, action):
        if self.use_pdu:
            action = f'pdu{action}'

        logging.debug(f'Setting power state to {action} for {self.xcat_name}')
        p = run(['ssh',  'xcat-b', '/opt/xcat/bin/rpower', self.xcat_name, action])

        return p.returncode == 0


class OzXcatSerial(OzXcat):
    def __init__(self, xcat_name, use_pdu=False):
        super().__init__(xcat_name, use_pdu)

    def log_console(self):
        serial_name = f'root:{self.xcat_name}@serial1'
        p = run(['getpassword', serial_name], capture_output=True)
        if p.returncode != 0:
            logging.error(f'No password available for {serial_name}')
            return
        password = p.stdout.decode('utf-8').strip()

        self.console = p = PexpectHelper()
        p.bug_patterns = []
        p.spawn(f'ssh root:{self.xcat_name}@serial1', timeout=30, quiet=True)
        p.log_to(open('console.log', 'w'))
        p.expect(r'\(%s\) Password:' % serial_name)
        p.send(password)
        p.send('\r')

        atexit.register(lambda: p.drain_and_terminate())


class PpmXcat:
    def __init__(self, xcat_name):
        self.xcat_name = xcat_name

    def log_console(self):
        self.console = p = PexpectHelper()
        p.bug_patterns = []
        p.spawn(f'congo console {self.xcat_name}', timeout=30, quiet=True)
        p.log_to(open('console.log', 'w'))
        atexit.register(lambda: p.drain_and_terminate())

    def close_console(self):
        self.console.drain_and_terminate()

    def get_power_state(self):
        logging.debug(f'Checking power state for {self.xcat_name}')

        p = run(['power-control.sh', self.xcat_name, 'stat'], capture_output=True)
        if p.returncode != 0:
            return None

        output = p.stdout.decode('utf-8')

        patterns = [
            # FSP
            r'Chassis Power is (on|off)',
            # OpenBMC eg: CurrentHostState    : xyz.openbmc_project.State.Host.HostState.Running
            r'CurrentHostState\s*: [a-zA-Z\.]+\.HostState\.(Running|Off)',
            # HMC
            r'(Running|Not Activated)',
        ]

        for pattern in patterns:
            match = re.compile(pattern).search(output)
            if match:
                val = match.group(1)
                if val in ['on', 'Running']:
                    return 'on'
                else:
                    return 'off'

        return 'unknown'

    def set_power_state(self, action):
        logging.debug(f'Setting power state to {action} for {self.xcat_name}')
        p = run(['power-control.sh', self.xcat_name, action])
        return p.returncode == 0


class BasicBoot:
    def __init__(self, full_hostname, xcat, image_dest, install_modules=True, image_src=None):
        self.full_hostname = full_hostname
        self.xcat = xcat
        self.image_dest = image_dest
        self.host_ssh_target = f'root@{full_hostname}'
        self.install_modules = install_modules
        self.image_src = image_src
        self.callbacks = []

        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('-v', dest='verbose', action='store_true', help='Verbose logging')
        self.parser.add_argument('--release-path', type=str, help='Path to kernel.release')
        self.parser.add_argument('--modules-path', type=str, help='Path to modules tarball')
        self.parser.add_argument('--kernel-path', type=str, required=True, help='Path to kernel (vmlinux or z/uImage)')

    def choose_boot_kernel(self, args):
        # Machine is configured to automatically boot the right kernel
        return True

    def waiting_in_firmware(self):
        # Assume not waiting in firmware
        return False

    def boot(self, args):
        logging.info(f"Booting {self.full_hostname}")

        if self.image_src:
            base = os.path.dirname(args.kernel_path)
            image_path = f'{base}/{self.image_src}'
        else:
            image_path = args.kernel_path

        run(['rsync', '-aL', image_path, self.image_dest], check=True, timeout=minutes(5))

        self.xcat.log_console()

        power_state = self.xcat.get_power_state()
        logging.info(f'Power state is {power_state}')

        reset = False
        if power_state == 'on':
            if self.waiting_in_firmware():
                logging.info("System already in firmware")
            else:
                logging.info("Rebooting via SSH")
                if reboot_host(self.host_ssh_target):
                    logging.info("Sleeping 2m while system reboots ...")
                    time.sleep(120)
                else:
                    reset = True
        elif power_state == 'off':
            logging.info("Powering on")
            if not self.xcat.set_power_state('on'):
                logging.error("Powering on failed? Waiting anyway ...")
            logging.info("Sleeping 1m while system powers on ...")
            time.sleep(60)
        else:
            reset = True

        if reset:
            logging.info("Resetting via power control")
            if not self.xcat.set_power_state('reset'):
                logging.error("Power reset failed? Waiting anyway ...")
            logging.info("Sleeping 2m while system resets ...")
            time.sleep(120)

        if not self.choose_boot_kernel(args):
            return False

        if not wait_for_ssh(self.host_ssh_target, 10, 30):
            return False

        if not check_uptime(self.host_ssh_target):
            return False

        if args.release_path:
            expected_release = open(args.release_path).read().strip()
            if not check_kernel_release(self.host_ssh_target, expected_release):
                return False

        cmds = ['set -x',
                'uptime',
                'cat /proc/uptime',
                'uname -a',
                'tail -11 /proc/cpuinfo',
               ]

        if args.modules_path and self.install_modules:
            logging.info("Copying modules ...")
            run(['scp', args.modules_path, f'{self.host_ssh_target}:/var/tmp/ngci-modules.tar.bz2'], check=True, timeout=minutes(5))
            cmds.extend([
                'cd /lib/modules',
                'tar --strip-components=2 -xf /var/tmp/ngci-modules.tar.bz2',
                'sync',
               ]
            )

        logging.info("Running host commands ...")
        if not run_ssh_cmd(self.host_ssh_target, ';'.join(cmds), timeout=minutes(5)):
            return False

        for func in self.callbacks:
            if not func(self):
                logging.error("Callback failed!")
                return False

        logging.info("Dumping dmesg ...")
        if not get_dmesg_via_ssh(self.host_ssh_target):
            return False

        logging.info("Checking dmesg for oops ...")
        if filter_log_warnings(open('dmesg.txt'), open('warnings.txt', 'w')):
            logging.error('Errors/warnings seen in console log')
            return False

        now = datetime.now()
        run_ssh_cmd(self.host_ssh_target, f"echo 'ngci: boot test finished OK {now}' > /dev/kmsg", timeout=minutes(1))

        self.xcat.close_console()

        logging.info("All OK!")

        return True

    def boot_main(self, orig_args):
        setup_logging()
        args = self.parser.parse_args(orig_args)
        return 0 if self.boot(args) else 1


class PowernvBoot(BasicBoot):
    def __init__(self, full_hostname, xcat, cmdline, image_dest, image_host):
        super().__init__(full_hostname, xcat, image_dest, install_modules=True)
        self.cmdline = cmdline
        self.image_host = image_host
        self.parser.add_argument('--use-initrd', dest='use_initrd', action='store_true', help='Use initrd')
        self.parser.add_argument('--cmdline', type=str, help='Extra kernel command line arguments')

    def waiting_in_firmware(self):
        return self.check_petitboot(60)

    def check_petitboot(self, timeout):
        logging.info("Checking for Petitboot ...")

        p = self.xcat.console
        p.push_prompt('# $')

        for attempt in range(0, 3):
            # Poke it to get some output if it's waiting for us
            p.send('\r')

            patterns = ["x=exit", "Exiting petitboot", p.prompt, "login:", "assword:", r"\(initramfs\)",
                        pexpect.TIMEOUT]

            i = p.expect(patterns, timeout=timeout)

            if i == 0:
                logging.info("Saw Petitboot x=exit, sending 'x' ...")
                time.sleep(1)
                p.send("x")
            elif i == 1:
                logging.info("Saw exiting petitboot")
            elif i == 2:
                logging.info("Saw shell prompt")
                p.send('\r')
            elif i == 3 or i == 4:
                logging.info("System at login prompt (probably host kernel)")
                return False
            elif i == 5:
                logging.info("System at initramfs prompt (usually bad)")
                return False
            elif i == 6:
                logging.error("Timeout waiting for petitboot!")
                continue

            i = p.expect([p.prompt, pexpect.TIMEOUT])
            if i == 0:
                break

        # op-build sets the hostname to skiroot
        p.send('hostname')
        i = p.expect(['skiroot', pexpect.TIMEOUT])
        if i == 0:
            logging.info("System in petitboot")
            return True

        logging.info("System at prompt but not skiroot?")
        return False

    def choose_boot_kernel(self, args):
        p = self.xcat.console

        # Drain any output from before we rebooted so that we don't see it when
        # waiting for petitboot.
        p.drain()

        for i in range(0, 3):
            if self.check_petitboot(timeout=240):
                break
        else:
            logging.error("Couldn't detect petitboot")
            return False

        p.cmd("nvram -p ibm,skiboot --print-config")

        logging.info("Waiting for network ...")
        network = False
        for _ in range(1, 30):
            p.send("ip -4 -o addr show scope global")
            i = p.expect(["inet", p.prompt, pexpect.TIMEOUT])
            if i == 0:
                network = True
                p.expect_prompt()
                break
            elif i == 1:
                pass
            else:
                logging.error("Timeout waiting for ip!")
                return False

            # Give the network time to come up
            time.sleep(2)

        if not network:
            logging.error("Timed out waiting to check ip status")
            return False

        logging.info("Got network")
        p.cmd("ip -4 addr show")
        p.cmd("rm -f vmlinux")

        url = f"http://{self.image_host}/{self.full_hostname}/vmlinux.dev"
        p.send(f"wget -q -O vmlinux --no-check-certificate {url}")
        p.expect_prompt(timeout=600)
        p.send("echo result=$?")
        i = p.expect(['result=0', pexpect.TIMEOUT])
        if i != 0:
            logging.error("wget of vmlinux failed!")
            return False

        p.expect_prompt()

        logging.info("Got vmlinux")
        p.cmd("md5sum vmlinux")

        initrd_arg = ''
        if args.use_initrd:
            initrd_url = f"http://{self.image_host}/{self.full_hostname}/initrd.img"
            p.send(f"wget -q -O initrd.img --no-check-certificate {initrd_url}")
            p.expect_prompt(timeout=600)
            p.send("echo result=$?")
            i = p.expect(['result=0', 'result=1', pexpect.TIMEOUT])
            if i == 0:
                initrd_arg = '-i initrd.img'
            elif i == 1:
                logging.info("wget of initrd failed.")
            else:
                logging.error("Timeout wgetting initrd!")
                return False
            p.expect_prompt()

        p.cmd("kexec -v")

        kernel_cmdline = self.cmdline
        if args.cmdline:
            kernel_cmdline += ' ' + args.cmdline

        p.send(f'kexec -s -c "{kernel_cmdline}" {initrd_arg} vmlinux')
        p.expect_prompt(timeout=60)
        p.send("echo result=$?")
        i = p.expect(['result=0', 'result=1', pexpect.TIMEOUT])
        if i == 1:
            # Try non-file-load kexec
            p.send(f'kexec -l -c "{kernel_cmdline}" {initrd_arg} vmlinux')
            p.expect_prompt(timeout=60)
            p.send("echo result=$?")
            i = p.expect(['result=0', 'result=1', pexpect.TIMEOUT])

        if i != 0:
            logging.error("kexec load failed")
            return False

        p.expect_prompt()

        logging.info("Loaded kexec kernel, booting ...")
        p.send("kexec -e")

        short_name = self.full_hostname.split('.')[0]

        i = p.expect([f"Ubuntu .* {self.full_hostname} ",
                      f"{short_name} login",
                       "Rebooting in .* seconds",
                       "UNEXPECTED INCONSISTENCY; RUN fsck MANUALLY.",
                       pexpect.TIMEOUT], timeout=600)

        if i == 0 or i == 1:
            logging.info("Got login prompt!")
        elif i == 2:
            logging.error("Saw oops after kexec!")
            return False
        elif i == 3:
            logging.error("File system need manual fsck!")
            return False
        else:
            logging.error("Timeout waiting for boot")
            return False

        return True
