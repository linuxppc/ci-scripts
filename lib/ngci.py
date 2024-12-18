#!/usr/bin/python3

import argparse
import sys
import logging
import os
import os.path
import re
import time
from copy import copy
from collections import OrderedDict
from datetime import datetime
from hashlib import sha1
from multiprocessing import Process, Pipe
from subprocess import check_output, call, run, DEVNULL, Popen, PIPE

import defaults
from qemu import kvm_present

try:
    from termcolor import colored
except ModuleNotFoundError:
    def colored(s, c):
        return s


def banner(msg, char='#', colour='yellow'):
    logging.info(colored(char * 60, colour))
    logging.info(colored('%s %-056s %s' % (char, msg, char), colour))
    logging.info(colored(char * 60, colour))


def ok():
    return colored('OK', 'green')


def get_git_rev(path):
    if os.path.isdir(path):
        cmd = 'git log -1 --oneline HEAD'
        result = run(cmd.split(), cwd=path, capture_output=True, check=True)
        return result.stdout.decode('utf-8').splitlines()[0]
    else:
        return None


def mkdirp(path):
    logging.debug('mkdir %s', path)
    os.makedirs(path, exist_ok=True)


class State:
    def __init__(self, script_dir, suite_name, args):
        self.src = args.src
        self.script_dir = script_dir

        output = args.output
        if output is None:
            output = os.getcwd()

        suite_name = suite_name.replace('/', '_').replace(' ', '_')
        self.output_dir = f'{output}/{suite_name}'
        self.dry_run = args.dry_run
        self.skip_boot = args.skip_boot
        self.build_dir = f'{self.output_dir}/build'
        self.boot_dir = f'{self.output_dir}/boot'
        self.config_dir = f'{script_dir}/etc/configs'
        self.kfactor = args.kfactor    # number of parallel builds
        self.jfactor = args.jfactor    # parallelism of each build
        self.bfactor = args.bfactor    # number of parallel boots
        self.kfilter = args.kfilter    # kernels to build
        self.sfilter = args.sfilter    # selftests to build
        self.bfilter = args.bfilter    # hosts to boot
        self.tfilter = args.tfilter    # tests to run


def defconfig_subarch(defconfig):
    ppc64le_configs = [
        'microwatt_defconfig',
        'powernv_defconfig',
        'pseries_le_defconfig',
        'skiroot_defconfig',
    ]

    ppc64_configs = [
        'allmodconfig',
        'allyesconfig',
        'cell_defconfig',
        'corenet64_smp_defconfig',
        'g5_defconfig',
        'pseries_defconfig',
        'ps3_defconfig',
    ]

    base_config = defconfig.split('+')[0]
    if defconfig.startswith('ppc64le') or base_config in ppc64le_configs:
        subarch = 'ppc64le'
    elif defconfig.startswith('ppc64') or base_config in ppc64_configs:
        subarch = 'ppc64'
    else:
        subarch = 'ppc'

    return subarch


class KernelBuild:
    def __init__(self, defconfig, image, merge_config=[], clang=False,
                 sparse=False, modules=True, llvm_ias=False):
        self.defconfig = defconfig
        self.image = image
        self.merge_config = merge_config
        self.clang = clang
        self.llvm_ias = llvm_ias
        self.sparse = sparse
        self.modules = modules

        subarch = defconfig_subarch(defconfig)
        self.subarch = subarch
        self.name = f'{defconfig}@{image}'

    def dir_name(self):
        # Has to match get_output_dir() in lib.sh
        defconfig_dir = self.defconfig.replace('/', '_')
        return f'{defconfig_dir}@{self.subarch}@{self.image}'

    def __eq__(self, other):
        # name covers defconfig and image
        return (self.name == other.name and
                self.subarch == other.subarch and
                self.merge_config == other.merge_config and
                self.clang == other.clang and
                self.llvm_ias == other.llvm_ias and
                self.sparse == other.sparse and
                self.modules == other.modules)

    def __str__(self):
        l = [self.name]
        if self.merge_config:
            l.append(f'merge_config={self.merge_config}')
        if self.clang:
            l.append('clang')
        if self.llvm_ias:
            l.append('llvm_ias')
        if self.sparse:
            l.append('sparse')
        if self.modules:
            l.append('modules')
            
        return '/'.join(l)


class SelftestsBuild:
    def __init__(self, image, subarch, target='selftests'):
        self.image = image
        self.subarch = subarch
        self.target = target

        self.full_image = f'{subarch}@{image}'
        if target == 'ppctests':
            target_dir = 'selftests_powerpc'
        else:
            target_dir = 'selftests'

        self.name = f'{target_dir}@{self.full_image}'
        self.output_dir = self.name


class BootConfig:
    def __init__(self, name, defconfig, image, script=None, tests=[], cmdline=None):
        self.name = name
        self.defconfig = defconfig
        self.image = image
        self.cmdline = cmdline
        self.tests = tests

        if script is None:
            script = name

        self.script = script

        subarch = defconfig_subarch(defconfig)
        self.subarch = subarch
        self.full_image = f'{subarch}@{image}'

    def __eq__(self, other):
        return (self.name == other.name and
                self.defconfig == other.defconfig and
                self.image == other.image and
                self.subarch == other.subarch and
                self.cmdline == other.cmdline and
                self.tests == other.tests and
                self.script == other.script)

    def __str__(self):
        l = [self.name, self.defconfig, self.image]
        return '/'.join(l)

    def dir_name(self):
        return f'{self.name}@{self.defconfig}@{self.image}'

    def get_args(self, state):
        return []

    def long_description(self):
        return f'{self.name} with {self.defconfig} using {self.script}'


class QemuBootConfig(BootConfig):
    def __init__(self, name, defconfig, image, script=None, tests=[],
                 qemu=None, cmdline=None):
        super().__init__(name, defconfig, image, script, tests, cmdline)
        if qemu in ['default', None]:
            qemu = defaults.QEMU_VERSION
        self.qemu_version = qemu
        self.callbacks = []
        self.args = []

    def __eq__(self, other):
        return (super().__eq__(other) and
                self.qemu_version == other.qemu_version)

    def __str__(self):
        l = [self.name, self.qemu_version, self.defconfig, self.image]
        return '/'.join(l)

    def long_description(self):
        return f'{self.name} with {self.defconfig} using {self.script} using qemu {self.qemu_version}'

    def dir_name(self):
        if self.qemu_version in ['mainline', 'host']:
            # Use it directly
            version = self.qemu_version
        elif re.compile(r'([0-9]\.)+').match(self.qemu_version):
            # It's a dotted version, use it directly
            version = self.qemu_version
        else:
            # It's a path or something else, generate a unique string based on it
            version = sha1(self.qemu_version.encode('utf-8')).hexdigest()[:12]
            version = f'custom-{version}'

        return f'{self.name}@qemu-{version}@{self.defconfig}@{self.image}'

    def get_args(self, state):
        args = copy(self.args)
        args.extend([f'--callback "{c}"' for c in self.callbacks])

        ver = self.qemu_version
        if self.qemu_version == 'host':
            # No qemu path needed, default to path lookup
            return args

        if self.qemu_version.startswith('/'):
            # Treat it as a full path to the bin directory
            path = self.qemu_version
        else:
            # Version number pointing to directory under external/qemu/
            path = f'{state.script_dir}/external/qemu/qemu-{ver}/install/bin'

        args.append(f'--qemu-path {path}')
        return args


class TestConfig:
    def __init__(self, name):
        self.name = name
        self.run = True

    def setup(self, state, boot, test_dir):
        gen_script(f'{test_dir}/run.sh', f'{state.script_dir}/scripts/test/{self.name} {boot.name}\n')
        pass


class SelftestsConfig(TestConfig):
    def __init__(self, name, selftest_build):
        super().__init__(name)
        self.name = name
        self.selftests = selftest_build

    def setup(self, state, boot, test_dir):
        selftests_tar = f'{state.build_dir}/{self.selftests.output_dir}/selftests.tar.gz'
        run(f'ln -sf {selftests_tar}'.split(), cwd=test_dir, check=True)
        gen_script(f'{test_dir}/run.sh', f'{state.script_dir}/scripts/test/{self.name} {boot.name}\n')


class QemuNetTestConfig(TestConfig):
    def __init__(self, enabled=True):
        super().__init__('qemu-net-tests')
        self.enabled = enabled
        self.run = False

    def setup(self, state, boot, test_dir):
        if self.enabled:
            boot.args.append('--net-tests')


class QemuTestConfig(TestConfig):
    def __init__(self, name, callbacks=[]):
        super().__init__(f'qemu-test-{name}')
        self.callbacks = callbacks

    def setup(self, state, boot, test_dir):
        start_marker = f'starting-{self.name}'
        end_marker = f'end-{self.name}'

        # Script doesn't run the tests, just greps the qemu console.log
        gen_script(f'{test_dir}/run.sh',
            f"awk '/{start_marker}/, /{end_marker}/' ../console.log | tee extracted.log")

        boot.callbacks.append(f'sh(# {start_marker})')
        for callback in self.callbacks:
            boot.callbacks.append(callback)
        boot.callbacks.append(f'sh(# {end_marker})')


class QemuSelftestsConfig(TestConfig):
    def __init__(self, selftest_build, collection=None, exclude=[], extra_callbacks=[]):
        name = 'qemu-selftests'
        if collection:
            s = collection.replace('/', '_').replace('.', '').replace('*', '')
            name = f'{name}-{s}'
        super().__init__(name)
        self.selftests = selftest_build
        self.collection = collection
        self.exclude = exclude
        self.extra_callbacks = extra_callbacks

    def setup(self, state, boot, test_dir):
        start_marker = f'starting-{self.name}'
        end_marker = f'end-{self.name}'

        # Script doesn't run the tests, just checks the qemu console.log for errors
        script = [
            f"awk '/{start_marker}/, /{end_marker}/' ../console.log | tee extracted.log",
            'grep "not ok" extracted.log && exit 1',
            'exit 0',
        ]

        gen_script(f'{test_dir}/run.sh', '\n'.join(script))

        selftests_tar = f'{state.build_dir}/{self.selftests.output_dir}/selftests.tar.gz'
        run(f'ln -sf {selftests_tar}'.split(), cwd=test_dir, check=True)

        # Pass selftest to qemu
        boot.args.append(f'--selftests-path {selftests_tar}')

        boot.callbacks.append(f'sh(# {start_marker})')
        for name in self.exclude:
            boot.callbacks.append(f"sh(sed -i -e '\\|^{name}$|d' /var/tmp/selftests/kselftest-list.txt)")

        if self.extra_callbacks:
            boot.callbacks.extend(self.extra_callbacks)

        if self.collection:
            cb = f'run_selftest_collections_nocheck({self.collection})'
        else:
            cb = 'run_selftests_nocheck'

        boot.callbacks.append(cb)
        boot.callbacks.append(f'sh(# {end_marker})')


class TestSuite:
    def __init__(self, name, continue_on_error=True, qemus=None):
        self.name = name
        self.continue_on_error = continue_on_error
        if not qemus:
            qemus = ['default']
        self.qemus = qemus
        self.kernels = OrderedDict()
        self.selftests = OrderedDict()
        self.boots = OrderedDict()

    def add_kernel(self, *args, **kwargs):
        k = KernelBuild(*args, **kwargs)
        self.__add_kernel(k)

    def __add_kernel(self, kernel):
        other = self.kernels.get(kernel.name, None)
        if other and other != kernel:
            raise Exception(f"Non-matching kernels with same name! {kernel} != {other}")
        self.kernels[kernel.name] = kernel

    def add_boot(self, *args, **kwargs):
        self.__add_boot(BootConfig(*args, **kwargs))

    def __add_boot(self, boot):
        other = self.boots.get(boot.dir_name(), None)
        if other and other != boot:
            raise Exception(f"Non-matching boots with same key! {boot} != {other}")
        boot.kernel_build = self.kernels[f'{boot.defconfig}@{boot.image}']
        self.boots[boot.dir_name()] = boot

    def add_qemu_boot(self, *args, **kwargs):
        for qemu in self.qemus:
            self.__add_boot(QemuBootConfig(*args, **kwargs, qemu=qemu))

    def add_selftest(self, *args, **kwargs):
        build = SelftestsBuild(*args, **kwargs)
        self.selftests[build.name] = build
        return build


def ngci_get_parser():
    parser = argparse.ArgumentParser(description='Not Good (Very Bad) CI harness')
    parser.add_argument('--dry-run', action='store_true', help='Dry run')
    parser.add_argument('-o', '--output', type=str, help='Output directory', default=None)
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose messages')
    parser.add_argument('-j', dest='jfactor', type=int, default=int(os.environ.get('JFACTOR', 1)),
                        help='Kernel build parallelism')
    parser.add_argument('-k', dest='kfactor', type=int, default=int(os.environ.get('KFACTOR', 1)),
                        help='Number of concurrent kernel builds')
    parser.add_argument('-b', dest='bfactor', type=int, default=int(os.environ.get('BFACTOR', 1)),
                        help='Number of concurrent boots')
    parser.add_argument('-K', dest='kfilter', type=str, default=None, action='append', help='Filter kernel builds')
    parser.add_argument('-S', dest='sfilter', type=str, default=None, action='append', help='Filter selftest builds')
    parser.add_argument('-B', dest='bfilter', type=str, default=None, action='append', help='Filter boots')
    parser.add_argument('-T', dest='tfilter', type=str, default=None, action='append', help='Filter tests to run')
    parser.add_argument('-i', dest='images',  type=str, default=[],   action='append', help='Images')
    parser.add_argument('-q', dest='qemus',   type=str, default=[], action='append', help='Qemu versions to test with')
    parser.add_argument('--skip-boot', action='store_true', help='Skip booting, just run tests')
    parser.add_argument('-t', '--test-suite', dest='test_suite', type=str, required=True, help='Test suite to run')
    parser.add_argument('src', type=str, help='Path to source repository')
    return parser


def ngci_main(orig_args):
    parser = ngci_get_parser()
    args = parser.parse_args(orig_args[1:])

    test_name = args.test_suite.replace('-', '_')
    if test_name.startswith('boot_'):
        test_name = test_name.split('_', 1)[1]

    import tests
    test_func = getattr(tests, test_name)

    return ngci_args(args, test_func(args))


def ngci_args(args, test_suite):
    level = logging.INFO
    if args.verbose:
        level = logging.DEBUG

    logging.basicConfig(format='%(levelname)s: %(asctime)s: %(message)s', level=level, datefmt='%H:%M:%S')

    if not os.path.exists(f'{args.src}/Makefile'):
        logging.error(f'src ({args.src}) does not point to a kernel directory?')
        return -1

    if os.path.exists(f'{args.src}/.config'):
        logging.error(colored('The source tree is not clean, please run make mrproper', 'red'))
        return -1

    # Assumes we're called from scripts/ngci/ngci directly or via symlink
    arg0_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
    script_dir = f'{arg0_dir}/../..'

    state = State(script_dir, test_suite.name, args)

    mkdirp(state.output_dir)
    logging.getLogger().addHandler(logging.FileHandler(filename=f'{state.output_dir}/log', mode='w'))

    banner(f'Test {test_suite.name} starting up', colour='yellow')
    logging.info('')

    logging.info(f'src:     {state.src}')
    logging.info(f'linux:   {get_git_rev(state.src)}')
    logging.info(f'output:  {state.output_dir}')
    logging.info(f'jfactor: {state.jfactor} # kernel build parallelism')
    logging.info(f'kfactor: {state.kfactor} # number of concurrent kernel builds')
    logging.info(f'bfactor: {state.bfactor} # number of concurrent boots')
    if state.kfilter:
        logging.info(f'kfilter: {state.kfilter} # kernel build filter')
    if state.sfilter:
        logging.info(f'sfilter: {state.sfilter} # selftest build filter')
    if state.bfilter:
        logging.info(f'bfilter: {state.bfilter} # boot filter')
    if state.tfilter:
        logging.info(f'tfilter: {state.tfilter} # test filter')
    if args.images:
        logging.info(f'images: {args.images}')
    logging.info('')

    if args.dry_run:
        banner("Dry run", colour='blue')

    if run_one_config(test_suite, state):
        return 0

    return -1


def run_one_config(test_suite, state):
    start = datetime.now()

    build_result = build(test_suite, state)
    if build_result:
        banner("OK", colour='green')
    elif test_suite.continue_on_error:
        banner("Failed - continuing", char='!', colour='red')

    if build_result or test_suite.continue_on_error:
        boot_result = boot_kernels(test_suite, state)

    if not build_result or not boot_result:
        banner("Failed", char='!', colour='red')
    else:
        banner("OK", colour='green')

    end = datetime.now()
    logging.info(f'Completed {test_suite.name} in {end - start}')

    return build_result


def filter_matches(name, filters):
    for f in filters:
        if f.startswith('!'):
            # easy filter out with !foo
            if f[1:] in name:
                return False
        else:
            # regex to filter in
            p = re.compile(f)
            if p.search(name):
                return True

    return False


def build(test_suite, state):
    banner('Building kernels & selftests ...')

    jobs = []
    for k in test_suite.kernels.values():
        if state.kfilter and not filter_matches(k.name, state.kfilter):
            logging.debug(f'Skipping kernel build {k.name} due to filter')
            continue
        jobs.append(Job(build_one_kernel, (state, k)))

    for s in test_suite.selftests.values():
        if state.sfilter and not filter_matches(s.target, state.sfilter):
            logging.debug(f'Skipping selftest build {s.target} due to filter')
            continue
        jobs.append(Job(build_one_selftest, (state, s)))

    result = run_jobs(jobs, state.kfactor, test_suite.continue_on_error)
    return result


def build_one_kernel(state, kernel, number, total):
    logging.info(f'Building {number}/{total} {kernel.name} ...')

    extra = f"-v {state.config_dir}:/configs:ro"
    os.environ['DOCKER_EXTRA_ARGS'] = extra

    base_cmd = ['make', '--no-print-directory', '-C', f'{state.script_dir}/build']
    base_cmd.append(f'SRC={state.src}')
    base_cmd.append(f'DEFCONFIG={kernel.defconfig}')
    base_cmd.append(f'CI_OUTPUT={state.build_dir}')
    base_cmd.append(f'JFACTOR={state.jfactor}')
    base_cmd.append('QUIET=1')

    if kernel.clang:
        base_cmd.append('CLANG=1')
        if kernel.llvm_ias:
            base_cmd.append('LLVM_IAS=1')
        else:
            base_cmd.append('LLVM_IAS=0')

    if kernel.sparse:
        base_cmd.append('SPARSE=1')

    full_image = f'{kernel.subarch}@{kernel.image}'
    cmd = copy(base_cmd)
    cmd.append(f'kernel@{full_image}')

    if kernel.modules:
        cmd.append('MODULES=1')

    if kernel.merge_config:
        configs = munge_configs(state, kernel.merge_config)
        if configs is None:
            return False
        val = ','.join(configs)
        cmd.append(f'MERGE_CONFIG={val}')

    if not state.dry_run:
        # Clean so a failed build doesn't leave old artifacts lying around
        clean_cmd = copy(base_cmd)
        clean_cmd.append(f'clean-kernel@{full_image}')
        logging.debug(clean_cmd)
        run(clean_cmd, stdin=DEVNULL, check=True)

    ci_output_dir = f'{state.build_dir}/{kernel.dir_name()}'
    mkdirp(ci_output_dir)
    log_path = f'{ci_output_dir}/log.txt'
    log = open(log_path, 'w')

    logging.debug(cmd)

    if state.dry_run:
        return True

    start = datetime.now()
    result = run(cmd, stdout=log, stderr=log, stdin=DEVNULL)
    end = datetime.now()

    if result.returncode != 0:
        log.close()
        logging.error(colored(f'Failed building {kernel.name}', 'red'))
        logging.info(f'See: {log_path}')
        dump_log(log_path)
        return False

    logging.info(f'{ok()} Build of {kernel.name} took {end - start}')

    cmd = copy(base_cmd)
    cmd.append(f'prune-kernel@{full_image}')
    logging.debug(cmd)
    run(cmd, stdout=log, stderr=log, stdin=DEVNULL, check=True)
    log.close()

    return True


def munge_configs(state, merge_config):
    l = []
    for path in merge_config:
        # Anything in a sub directory is from the kernel source
        if '/' in path:
            if not os.path.exists(f'{state.src}/{path}'):
                logging.error(f"Couldn't find config {path} in Linux source")
                return None

            path = f'/linux/{path}'
        else:
            if not path.endswith('.config'):
                path += '.config'

            if not os.path.exists(f'{state.config_dir}/{path}'):
                logging.error(f"Couldn't find config {path} in etc/configs")
                return None

            path = f'/configs/{path}'

        l.append(path)

    return l


def build_one_selftest(state, selftest, number, total):
    logging.info(f'Building {number}/{total} {selftest.target} for {selftest.full_image} ...')

    base_cmd = ['make', '--no-print-directory', '-C', f'{state.script_dir}/build']
    base_cmd.append(f'SRC={state.src}')
    base_cmd.append(f'CI_OUTPUT={state.build_dir}')
    base_cmd.append(f'JFACTOR={state.jfactor}')
    base_cmd.append('QUIET=1')

    if selftest.target == 'ppctests':
        base_cmd.append('TARGETS=powerpc')

    cmd = copy(base_cmd)
    cmd.append('INSTALL=1')
    cmd.append(f'{selftest.target}@{selftest.full_image}')

    if not state.dry_run:
        # Clean so a failed build doesn't leave old artifacts lying around
        clean_cmd = copy(base_cmd)
        clean_cmd.append(f'clean-selftests@{selftest.full_image}')
        logging.debug(clean_cmd)
        run(clean_cmd, stdin=DEVNULL, check=True)

    ci_output_dir = f'{state.build_dir}/{selftest.output_dir}'
    mkdirp(ci_output_dir)
    log_path = f'{ci_output_dir}/log.txt'
    log = open(log_path, 'w')

    logging.debug(cmd)

    if state.dry_run:
        return True

    start = datetime.now()
    result = run(cmd, stdout=log, stderr=log, stdin=DEVNULL)
    end = datetime.now()

    if result.returncode != 0:
        log.close()
        logging.error(colored(f'Failed building {selftest.target}', 'red'))
        logging.info(f'See: {log_path}')
        dump_log(log_path)
        return False

    logging.info(f'{ok()} Build of {selftest.target} for {selftest.full_image} took {end - start}')

    cmd = copy(base_cmd)
    cmd.append(f'prune-selftests@{selftest.full_image}')
    logging.debug(cmd)
    run(cmd, stdout=log, stderr=log, stdin=DEVNULL, check=True)
    log.close()

    return True

def boot_kernels(test_suite, state):
    if len(test_suite.boots) == 0:
        return True

    banner('Booting kernels ...')

    mkdirp(f'{state.boot_dir}')

    n = 1
    jobs = []
    have_kvm = kvm_present()
    pattern = re.compile('\\bkvm\\b')
    for boot in test_suite.boots.values():
        if state.bfilter and not filter_matches(boot.name, state.bfilter):
            logging.debug(f'Skipping boot of {boot.name} due to filter')
            continue

        if pattern.search(boot.script) and not have_kvm:
            logging.warn(colored(f'Skipping boot of {boot.name} due to KVM not present', 'yellow'))
            continue

        logging.debug(f'Adding boot job {boot.name}')
        jobs.append(Job(boot_and_test, (state, boot)))

    result = run_jobs(jobs, state.bfactor, test_suite.continue_on_error)
    return result


def boot_and_test(state, boot, number, total):
    host_dir = f'{state.boot_dir}/{boot.dir_name()}'
    mkdirp(host_dir)

    for test in boot.tests:
        if state.tfilter and not filter_matches(test.name, state.tfilter):
            logging.debug(f'Skipping test {test.name} due to filter')
            continue
        test_dir = f'{host_dir}/test-{test.name}'
        mkdirp(test_dir)
        test.setup(state, boot, test_dir)

    if state.skip_boot:
        logging.info('Skipping boot')
    elif not boot_host(state, boot, host_dir, number, total):
        return False

    return run_tests(state, boot, host_dir)


def boot_host(state, boot, host_dir, number, total):
    boot_script_path = f'{state.script_dir}/scripts/boot/{boot.script}'
    if not os.path.exists(boot_script_path):
        logging.error(f"Boot script '{boot_script_path}' doesn't exist")
        return False

    if state.dry_run:
        logging.info(f'Would boot {boot.long_description()} ...')
        return True

    logging.info(f'Booting {number}/{total} {boot.long_description()} ...')

    artifact_dir = f'{state.build_dir}/{boot.kernel_build.dir_name()}'

    if not os.path.exists(f'{artifact_dir}/vmlinux'):
        # vmlinux should exist even if we're booting a zImage/uImage
        logging.error(colored(f"Error: missing build artifacts for {boot.defconfig}", 'red'))
        return False

    run(f'ln -sf -T {artifact_dir} artifacts'.split(), cwd=host_dir, check=True)

    boot_args = [
        f'--kernel-path {artifact_dir}/vmlinux',
        f'--modules-path {artifact_dir}/modules.tar.gz',
        f'--release-path {artifact_dir}/kernel.release'
    ]

    if boot.cmdline:
        boot_args.append(f'--cmdline {boot.cmdline}')

    boot_args.extend(boot.get_args(state))
    boot_args.append('$@')
    boot_args = ' \\\n  '.join(boot_args)

    gen_script(f'{host_dir}/boot.sh', f'{boot_script_path} \\\n  {boot_args}\n')

    log_path = f'{host_dir}/log.txt'
    log = open(log_path, 'w')

    start = datetime.now()
    result = run(['./boot.sh'], cwd=host_dir, stdout=log, stderr=log, stdin=None)
    end = datetime.now()
    log.close()

    if result.returncode != 0:
        logging.error(colored(f'Failed booting {boot.name}, took {end - start}', 'red'))
        logging.info(f'See: {log_path}')
        dump_log(log_path)
        return False

    logging.info(f'{ok()} Booted {boot.name}, took {end - start}')
    return True


def run_tests(state, boot, host_dir):
    result = True
    for test in boot.tests:
        if not test.run:
            # Skip tests that only need to do setup, eg. qemu tests
            continue
        
        if state.tfilter and not filter_matches(test.name, state.tfilter):
            logging.debug(f'Skipping test {test.name} due to filter')
            continue

        if state.dry_run:
            logging.info(f'Would run {test.name} on {boot.name} ...')
            continue

        logging.info(f'Testing {test.name} on {boot.name} ...')

        test_dir = f'{host_dir}/test-{test.name}'
        test_log_path = f'{test_dir}/log.txt'
        test_log = open(test_log_path, 'w')

        test_start = datetime.now()
        proc = run(['./run.sh'], cwd=test_dir, stdout=test_log, stderr=test_log, stdin=None)
        test_end = datetime.now()

        if proc.returncode != 0:
            msg = f'Failed running test {test.name} on {boot.name} took {test_end - test_start}'
            logging.error(colored(msg, 'red'))
        else:
            base_msg = f'running test {test.name} on {boot.name} took {test_end - test_start}'
            logging.info(f'{ok()} {base_msg}')
            msg = f'OK {base_msg}' # no colour for log files

        print(msg, file=test_log)
        test_log.close()
        host_log = open(f'{host_dir}/log.txt', 'a')
        print(msg, file=host_log)
        host_log.close()

        if proc.returncode != 0:
            logging.info(f'See: {test_log_path}')
            dump_log(test_log_path)
            result = False

    return result


def gen_script(fname, body):
    f = open(fname, 'w')
    f.write('#!/bin/bash\n\n')
    f.write('[ -e environ ] && source environ\n\n')
    f.write('date\n\n')
    f.write(body)
    os.fchmod(f.fileno(), 0o700)
    f.close()


def dump_log(path, message=None):
    lines = open(path).readlines()
    total = len(lines)
    if total == 0:
        return

    if message:
        logging.info(message)

    if total > 50:
        lines = lines[-50:]
        logging.info(f'(skipped {total - 50} lines) ...')

    logging.info('%s' % ''.join(lines))


class Job:
    def __init__(self, func, args):
        self.func = func
        self.args = args

    def run(self, number, total):
        def f():
            return sys.exit(0 if self.func(*self.args, number, total) else 1)

        self.proc = Process(target=f)
        self.proc.start()


# make -j in python ¯\_(ツ)_/¯
def run_jobs(jobs, factor, continue_on_error):
    if factor == 0:
        factor = len(jobs)

    n = 1
    total = len(jobs)
    result = True
    running = []

    def wait_for_one_job(timeout=None):
        job = running.pop(0)
        job.proc.join(timeout)
        if job.proc.exitcode is None:
            # Didn't exit, put it at the back
            running.append(job)
            return None
        return job.proc.exitcode == 0

    while len(jobs) and (result or continue_on_error):
        while len(running) < factor and len(jobs):
            try:
                job = jobs.pop(0)
            except IndexError:
                break

            job.run(n, total)
            running.append(job)
            logging.debug(f'Started job {n}, running = {len(running)}')
            n += 1

        logging.debug(f'Waiting for a job to complete, running = {len(running)}')
        job_result = wait_for_one_job(10)
        if job_result is not None:
            result &= job_result

    while len(running):
        logging.debug(f'Waiting for a job to complete, running = {len(running)}')
        result &= wait_for_one_job()

    return result
