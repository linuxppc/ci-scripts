import logging
import pexpect
import sys
import time


class PexpectHelper:
    default_bug_patterns = [
        r'Unable to handle kernel paging request',
        r'Oops: Kernel access of bad area',
        r'Kernel panic - not syncing:',
        r'------------\[ cut here \]------------',
        r'\( 700 \) Program Exception',
    ]

    def __init__(self):
        self.child = None
        self.prompt = None
        self.prompt_stack = []
        self.bug_patterns = self.default_bug_patterns

    def spawn(self, *args, **kwargs):
        logging.debug("Spawning '%s'" % args)
        quiet = kwargs.pop('quiet', False)
        self.child = pexpect.spawn(*args, encoding='utf-8', codec_errors='replace',
                                   echo=False, **kwargs)
        if not quiet:
            self.log_to(sys.stdout)

    def log_to(self, output_file):
        self.child.logfile_read = output_file

    def wait_for_exit(self, timeout=-1):
        self.child.expect(pexpect.EOF, timeout=timeout)
        self.child.wait()

    def terminate(self):
        self.child.terminate()
        self.wait_for_exit()

    def drain(self):
        # Wait for 10s out of output, which should give oopses time to be logged
        self.child.expect([pexpect.TIMEOUT, pexpect.EOF], timeout=10)

    def drain_and_terminate(self):
        self.drain()
        self.terminate()

    def get_match(self, i=0):
        return self.child.match.group(i)

    def matches(self):
        return self.child.match.groups()

    def expect(self, patterns, timeout=-1, bug_patterns=None):
        if type(patterns) is str:
            patterns = [patterns]

        if bug_patterns is None:
            bug_patterns = self.bug_patterns

        patterns.extend(bug_patterns)

        idx = self.child.expect(patterns, timeout=timeout)
        if self.child.match == pexpect.TIMEOUT:
            logging.debug("Timed out looking for a match")
        else:
            logging.debug("Matched: '%s' %s", self.get_match(), self.matches())

        if idx >= len(patterns) - len(bug_patterns):
            msg = "Error: saw oops/warning etc. while expecting"
            logging.error(msg)
            self.drain_and_terminate()
            raise Exception(msg)

        return idx

    def push_prompt(self, prompt):
        self.prompt = prompt
        self.prompt_stack.append(prompt)

    def pop_prompt(self):
        self.prompt_stack.pop()
        self.prompt = self.prompt_stack[-1]

    def expect_prompt(self, timeout=-1):
        self.expect(self.prompt, timeout=timeout)

    def send_no_newline(self, data):
        self.child.send(data)

    def send(self, data):
        logging.debug("# sending: %s", data)
        self.child.send(data + '\r')

    def cmd(self, cmd):
        self.send(cmd)
        self.expect_prompt()


def standard_boot(p, login=False, user='root', password=None, timeout=-1):
    logging.info("Waiting for kernel to boot")
    i = p.expect([p.prompt, "login:", "Freeing unused kernel "], timeout=timeout)

    if i == 0 and not login:
        # We booted straight to a prompt, we're done
        logging.info("Booted direct to shell prompt")
        return

    if login:
        if i != 1:
            logging.info("Kernel came up, waiting for login ...")
            p.expect("login:", timeout=timeout)

        p.send(user)
        if password is not None:
            p.expect("Password:", timeout=timeout)
            p.send(password)

        p.expect_prompt(timeout=timeout)
    else:
        logging.info("Kernel came up, waiting for prompt ...")
        p.expect_prompt(timeout=timeout)

    logging.info("Booted to shell prompt")


def ping_test(p, ip='10.0.2.2', check=True):
    p.send(f'ping -W 10 -c 3 {ip}')
    if check:
        # busybox ping prints "packets received", iputils-ping does not
        p.expect('3 packets transmitted, 3( packets)? received')
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
    p.expect("di %x 1\\s+%x\\s+([a-f0-9]+)\\s+([\\.a-z].*)\r" % (addr, addr))
    result = [s.strip() for s in p.matches()]
    p.expect_prompt()

    xmon_exit(p)

    return result


def ignore_warnings(p, f):
    p.cmd('echo "#@@@ ignore warnings @@@#"')
    bug_patterns = p.bug_patterns
    p.bug_patterns = []
    f(p)
    p.bug_patterns = bug_patterns
    p.cmd('echo "#@@@ detect warnings @@@#"')
