import os
import logging
import signal
import struct
import sys
import time
from datetime import datetime


def setup_logging(format='%(levelname)s: %(message)s'):
     level = logging.INFO
     if '-v' in sys.argv:
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
    env = get_env_var('KBUILD_OUTPUT', None)
    if env:
        path = f'{env}/vmlinux'
        if os.path.isfile(path):
            return path

    path = 'vmlinux'
    if os.path.isfile(path):
        return path

    return None


def get_tarball(basename):
    dirs = ['.']
    env = get_env_var('KBUILD_OUTPUT', None)
    if env:
        dirs.append(env)

    for base in dirs:
        for suffix in ['gz', 'bz2', 'xz']:
            name = f'{base}/{basename}.tar.{suffix}'
            if os.path.isfile(name):
                return name

    return None


def get_modules_tarball():
    return get_tarball('modules')


def get_selftests_tarball():
    return get_tarball('selftests')

def read_expected_release(path):
    expected_release = open(path).read().strip()
    return expected_release


def get_expected_release():
    candidates = []
    default_path = 'include/config/kernel.release'
    env = os.environ.get('KBUILD_OUTPUT', None)
    if env:
        candidates.append(f'{env}/{default_path}')

    candidates.extend([default_path, 'kernel.release'])
    for path in candidates:
        if os.path.isfile(path):
            return read_expected_release(path)

    return None


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
    ignore_start = parser['ignore']['start']
    ignore_stop = parser['ignore']['stop']
    suppressions = [t[1] for t in parser.items('suppressions', [])]
    suppression_patterns = [t[1] for t in parser.items('suppression_patterns', [])]
    suppression_patterns = [re.compile(p) for p in suppression_patterns]
    strings  = [t[1] for t in parser.items('strings', [])]
    patterns = [t[1] for t in parser.items('patterns', [])]
    patterns = [re.compile(p) for p in patterns]

    def suppress(line):
        for suppression in suppressions:
            if suppression in line:
                return True

        for pattern in suppression_patterns:
            if pattern.search(line):
                return True

        return False

    found = False
    ignoring = False
    while True:
        line = infile.readline()
        if len(line) == 0:
            break

        if ignore_stop in line:
            ignoring = False
        elif not ignoring and ignore_start in line:
            ignoring = True

        if ignoring:
            continue
            
        if suppress(line):
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
