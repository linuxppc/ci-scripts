import logging
import pexpect
import sys
import time
from utils import debug_level


class PexpectHelper:
    DEFAULT_PROMPT = "/ #"

    default_bug_patterns = [
        'Unable to handle kernel paging request',
        'Oops: Kernel access of bad area',
        'Kernel panic - not syncing:',
        '------------\[ cut here \]------------',
        '\( 700 \) Program Exception',
    ]

    def __init__(self):
        self.child = None
        self.prompt = None
        self.prompt_stack = []
        self.bug_patterns = self.default_bug_patterns

    def spawn(self, *args, **kwargs):
        logging.debug("Spawning '%s'" % args)
        self.child = pexpect.spawn(*args, timeout=60, encoding='utf-8', echo=False, **kwargs)
        if '--quiet' not in sys.argv:
            self.log_to(sys.stdout)

    def log_to(self, output_file):
        self.child.logfile_read = output_file

    def wait_for_exit(self):
        self.child.expect(pexpect.EOF)
        self.child.wait()

    def terminate(self):
        self.child.terminate()
        self.wait_for_exit()

    def drain_and_terminate(self, child, msg):
        logging.error(msg)

        # Wait for the end of the oops, if it is one
        try:
            idx = self.child.expect(['--\[ end trace', pexpect.TIMEOUT], timeout=10)
        except pexpect.exceptions.EOF:
            idx = -1
            pass

        if idx == 1:
            # That didn't match, let it run for a bit
            time.sleep(5)

        self.terminate()
        raise Exception(msg)

    def get_match(self, i=0):
        return self.child.match.group(i)

    def matches(self):
        return self.child.match.groups()

    def expect(self, patterns, timeout=-1):
        if type(patterns) is str:
            patterns = [patterns]

        patterns.extend(self.bug_patterns)
        idx = self.child.expect(patterns, timeout=timeout)
        logging.debug("Matched: '%s' %s", self.get_match(), self.matches())

        if idx >= len(patterns) - len(self.bug_patterns):
            self.drain_and_terminate(self.child, "Error: saw oops/warning etc. while expecting")

        return idx

    def push_prompt(self, prompt):
        self.prompt = prompt
        self.prompt_stack.append(prompt)

    def pop_prompt(self):
        self.prompt_stack.pop()
        self.prompt = self.prompt_stack[-1]

    def expect_prompt(self):
        self.expect(self.prompt)

    def send_no_newline(self, data):
        self.child.send(data)

    def send(self, data):
        logging.debug("# sending: %s", data)
        self.child.send(data + '\r')

    def cmd(self, cmd):
        self.send(cmd)
        self.expect_prompt()


def standard_boot(p, login=False, user='root'):
    p.push_prompt(p.DEFAULT_PROMPT)

    logging.info("Waiting for kernel to boot")
    p.expect("Freeing unused kernel memory:")

    if login:
        logging.info("Kernel came up, waiting for login ...")
        p.expect("login:")
        p.send(user)
    else:
        logging.info("Kernel came up, waiting for prompt ...")

    p.expect_prompt()
    logging.info("Booted to shell prompt")


def ping_test(p, ip='10.0.2.2', check=True):
    p.send(f'ping -c 3 {ip}')
    if check:
        p.expect('3 packets transmitted, 3 packets received')
    p.expect_prompt()


def wget_test(p, check=False):
    # With busybox wget this will fail to download because it redirects to
    # https, but it still sends some packets so adds coverage.
    p.send('wget -S http://1.1.1.1')
    if check:
        p.expect('HTTP/1.1 301 Moved Permanently')
    p.expect_prompt()


def get_proc_version(p):
    p.send("cat /proc/version")
    p.expect("Linux version (([^ ]+)[^\r]+)\r")
    val = p.matches()
    p.expect_prompt()
    return val


def get_arch(p):
    p.send("uname -m")
    p.expect("(ppc64|ppc64le|ppc)\r")
    val = p.get_match(1).strip()
    p.expect_prompt()
    return val


def dot_sym(name, subarch):
    if subarch == 'ppc64':
        name = f'.{name}'
    return name


def disable_netcon(p):
    p.cmd("sed -i -e 's/^netcon/#netcon/' /etc/inittab")
    p.cmd("kill -HUP 1")


def show_opal_fw_features(p):
    p.cmd('ls --color=never /proc/device-tree/ibm,opal/fw-features/*/enabled')
    p.cmd('ls --color=never /proc/device-tree/ibm,opal/fw-features/*/disabled')


def xmon_enter(p):
    p.cmd("echo 1 > /proc/sys/kernel/sysrq")
    p.push_prompt("mon>")
    p.cmd("echo x > /proc/sysrq-trigger")


def xmon_exit(p):
    p.send("x")
    p.pop_prompt()
    p.expect_prompt()


def xmon_di(p, addr):
    xmon_enter(p)

    p.send("di %x 1" % addr)
    p.expect("di %x 1\s+%x\s+([a-f0-9]+)\s+([\.a-z].*)\r" % (addr, addr))
    result = [s.strip() for s in p.matches()]
    p.expect_prompt()

    xmon_exit(p)

    return result

