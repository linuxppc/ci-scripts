import os
import logging
import signal
import struct
import sys
import time
from datetime import datetime


def debug_level():
    if '-v' in sys.argv:
        return 1
    if '-vv' in sys.argv:
        return 2
    return 0


def setup_logging(format='%(levelname)s: %(message)s'):
     level = logging.INFO
     if debug_level() >= 1:
        level = logging.DEBUG

     logging.basicConfig(format=format, level=level, stream=sys.stdout)


def timeout_handler(signum, frame):
    logging.error('Timeout ! Exiting')
    sys.exit(1)


def setup_timeout(timeout_seconds):
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout_seconds)


def test_name():
     return os.path.splitext(os.path.basename(sys.argv[0]))[0]


def success():
     print("success: %s" % test_name())


def skip():
     print("skip: %s" % test_name())


def failure():
     print("failure: %s" % test_name())


def get_env_var(name, default=None):
    val = os.environ.get(name, None)
    if val:
        logging.debug("Using env[%s] = '%s'", name, val)
        return val

    return default


def check_env_vars(names):
    for name in names:
        val = os.environ.get(name, None)
        if val is None:
            logging.error(f'Environment variable {name} not set!')
            return False

    return True


def get_vmlinux():
    vmlinux = get_env_var('VMLINUX_PATH', 'vmlinux')
    if not os.path.isfile(vmlinux):
        logging.error("Can't read kernel 'vmlinux'! Try setting VMLINUX_PATH")
        return None

    return vmlinux


def get_expected_release():
    path = os.environ.get('KERNEL_RELEASE_PATH', None)
    if path is None:
        # Assume we're running in the kernel build directory
        path = 'include/config/kernel.release'
        msg = f"Couldn't read {path}, export KERNEL_RELEASE_PATH"
    else:
        msg = f"Couldn't read KERNEL_RELEASE_PATH {path}"

    if not os.path.isfile(path):
        logging.error(msg)
        return None

    expected_release = open(path).read().strip()
    logging.info(f'Looking for kernel version: {expected_release}')
    return expected_release


def test_harness(func, name, *args, **kwargs):
    tokens = ['test', name]
    for name, val in kwargs.items():
        if type(val) is bool:
            if val:
                tokens.append(name)
        else:
            tokens.append('%s=%s' % (name, val))

    name = '-'.join(tokens)

    start = datetime.now()

    print('test: %s' % name)
    try:
        rc = func(name, *args, **kwargs)
    except Exception as e:
        print('failure: %s' % name)
        raise e

    end = datetime.now()
    logging.debug(f'{name} took {end - start}')

    if rc:
        print('success: %s' % name)
    elif rc is None:
        print('skip: %s' % name)
        rc = True
    else:
        print('failure: %s' % name)

    return rc


def filter_log_warnings(infile, outfile):
    from configparser import ConfigParser
    import re

    base = os.path.dirname(sys.argv[0])
    path = os.path.join(base, '../etc/filters.ini')
    if not os.path.exists(path):
        path = os.path.join(base, '../../etc/filters.ini')

    parser = ConfigParser()
    parser.read_file(open(path))
    suppressions = [t[1] for t in parser.items('suppressions', [])]
    strings  = [t[1] for t in parser.items('strings', [])]
    patterns = [t[1] for t in parser.items('patterns', [])]
    patterns = [re.compile(p) for p in patterns]

    found = False
    while True:
        line = infile.readline()
        if len(line) == 0:
            break

        for suppression in suppressions:
            if suppression in line:
                continue

        for string in strings:
            if string in line:
                found = True
                outfile.write(line)
                continue

        for pattern in patterns:
            if pattern.search(line):
                found = True
                outfile.write(line)
                continue

    return found


def get_endian(elf_path):
    data = open(elf_path, 'rb').read(6)
    vals = struct.unpack('6B', data)

    if vals[0:4] != (127, 69, 76, 70):
        raise Exception('Not an ELF?')

    if vals[5] == 2:
        return 'big'
    elif vals[5] == 1:
        return 'little'
    else:
        Exception('Unknown endian')
