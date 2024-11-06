import logging
from utils import setup_timeout
from pexpect_utils import ignore_warnings

########################################
# Callbacks that can run once the VM has booted
#
# Use with the --callback argument. More than one can be specified.
########################################

# Run a shell command
# eg. --callback "sh(ls /dev)"
def sh(qconf, p, arg):
    p.send(f'{arg}')
    p.expect(p.prompt, timeout=None)
    return True

# Set the script timeout, in seconds, 0 for no timeout.
def set_timeout(qconf, p, arg):
    setup_timeout(int(arg))
    return True

# Mount debugfs and cat a file under it
# eg. --callback "cat_debugfs(powerpc/security_features)"
# eg. --callback "cat_debugfs(kernel_page_tables)"
def cat_debugfs(qconf, p, arg):
    p.cmd('mount -t debugfs none /sys/kernel/debug')
    # Clear timeout, we don't know how long it will take
    setup_timeout(0)
    p.send(f'cat /sys/kernel/debug/{arg}')
    p.expect_prompt(timeout=None)
    return True

# Check /proc/config.gz for a symbol
# eg. --callback "check_config(PREEMPT)"
def check_config(qconf, p, arg):
    p.cmd(f'zcat /proc/config.gz | grep {arg}')
    return True

# Run one or more selftest collections
# eg. --callback "run_selftest_collections(rlimits size)"
def run_selftest_collections(qconf, p, arg, check=True):
    collections = []
    for name in arg.split(' '):
        collections.append(name)
        
    return __run_selftests(qconf, p, collections=collections, check=check)

def run_selftest_collections_nocheck(qconf, p, arg):
    return run_selftest_collections(qconf, p, arg, check=False)

# Run all powerpc selftests
# eg. --callback run_ppctests
def run_ppctests(qconf, p):
    return __run_selftests(qconf, p, collections=['powerpc.*'])


# Run one or more individual selftests
# eg. --callback "run_selftests(powerpc/math:fpu_syscall core:close_range_test)"
def run_selftests(qconf, p, arg=None, check=True):
    if arg:
        tests = []
        for name in arg.split(' '):
            tests.append(name)

        return __run_selftests(qconf, p, tests=tests, check=check)

    return __run_selftests(qconf, p, check=check)


def run_selftests_nocheck(qconf, p, arg=None):
    return run_selftests(qconf, p, arg, check=False)


# KASAN Kunit test, needs modules
def kasan_kunit(qconf, p):
    ignore_warnings(p, lambda p: p.cmd('modprobe kasan_test'))
    return True


# Invoke lkdtm via sysfs
# eg. --callback "lkdtm(BUG WARNING)"
def lkdtm(qconf, p, arg):
    p.cmd('modprobe lkdtm')
    p.cmd('mount -t debugfs none /sys/kernel/debug')
    for word in arg.split():
        p.send(f'sh -c "echo {word} > /sys/kernel/debug/provoke-crash/DIRECT"')
        p.expect(p.prompt, bug_patterns=[])
    return True


# Run some or all lkdtm selftests
# eg. --callback "lkdtm_selftests()"
# eg. --callback "lkdtm_selftests(BUG WARNING)"
def lkdtm_selftests(qconf, p, arg=None):
    if arg:
        tests = [f'lkdtm:{t}.sh' for t in arg.split(' ')]
        return __run_selftests(qconf, p, tests=tests)

    return __run_selftests(qconf, p, collections=['lkdtm'])

########################################
# Helper functions
########################################

# Not a callback
def __run_selftests(qconf, p, tests=None, collections=None, check=True):
    # Clear timeout, we don't know how long it will take
    setup_timeout(0)

    # Lots of selftests need debugfs, make sure its mounted
    p.cmd('mount -t debugfs none /sys/kernel/debug')

    if tests:
        logging.info(f'Running individual selftests {", ".join(tests)}')
        arg = f'-t {" -t ".join(tests)}'
    elif collections:
        formatted = ', '.join(collections)
        logging.info(f'Running selftest collections {formatted}')
        arg = f'-c {" -c ".join(collections)}'
    else:
        logging.info('Running selftests')
        arg = ''

    p.send(f'/var/tmp/selftests/run_kselftest.sh {arg} | tee test.log')
    p.expect(p.prompt, timeout=None, bug_patterns=[])

    if check:
        p.send('grep "^[n]ot ok" test.log')
        idx = p.expect(['not ok', p.prompt])
        if idx == 0:
            return False

    return True
