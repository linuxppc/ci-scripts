from ngci import *
from configs import *
from defaults import *
from qemu import kvm_present


def std_images(args):
    if args.images:
        return args.images

    return DEFAULT_IMAGES


def sparse_image(images):
    for image in images:
        if image in SPARSE_IMAGES:
            return image
    return None


def clang_image(images):
    for image in images:
        if image in CLANG_IMAGES:
            return image
    return None


# Check that `image` is at least as new as one of the images
# in the `versions` list.
def image_at_least(image, versions):
    # Split the image into the name and optional version number
    parts = image.split('@')
    iname = parts[0]
    if len(parts) == 2:
        iversion = int(parts[1].replace('.', ''))
    else:
        iversion = None

    for version in versions:
        vname, vver = version.split('@')

        # If the names don't match continue
        if iname != vname:
            continue

        # If the input image has no version it's implicitly the latest, so
        # assume it's sufficiently new.
        if iversion is None:
            return True

        # Compare the version numbers
        vver = int(vver.replace('.', ''))
        if iversion >= vver:
            return True

    return False


def qemu_coverage(args, suite=None):
    images = std_images(args)
    if suite is None:
        suite = TestSuite('qemu-coverage', qemus=args.qemus)

    k = suite.add_kernel
    b = suite.add_qemu_boot

    have_kvm = kvm_present()
    if have_kvm:
        accel = 'kvm'
    else:
        accel = 'tcg'

    image = clang_image(images)
    # Clang builds & boots
    if image:
        k('ppc64le_guest_defconfig+clang', image, merge_config=guest_configs, clang=True)
        k('ppc64_guest_defconfig+clang', image, merge_config=guest_configs, clang=True)
        k('corenet64_smp_defconfig+clang', image, merge_config=corenet64_configs + ['disable-werror'], clang=True)
        k('corenet32_smp_defconfig+clang', image, merge_config=['debug-info-n', 'ppc64e-qemu', 'disable-werror'], clang=True)
        k('pmac32_defconfig+clang', image, merge_config=pmac32_configs + ['disable-werror'], clang=True)
        k('g5_defconfig+clang', image, merge_config=g5_configs + ['disable-werror'], clang=True)

        b('qemu-mac99',           'pmac32_defconfig+clang', image)
        b('qemu-g5',              'g5_defconfig+clang', image)
        # Doesn't boot
        # b('qemu-e500mc',        'corenet32_smp_defconfig+clang', image)
        b('qemu-ppc64e',          'corenet64_smp_defconfig+clang', image)
        b('qemu-pseries+p10+tcg', 'ppc64le_guest_defconfig+clang', image)
        b('qemu-powernv+p10+tcg', 'ppc64le_guest_defconfig+clang', image)

        b(f'qemu-pseries+p8+{accel}', 'ppc64le_guest_defconfig+clang', image)
        b(f'qemu-pseries+p9+{accel}', 'ppc64le_guest_defconfig+clang', image)
        b(f'qemu-pseries+p8+{accel}', 'ppc64_guest_defconfig+clang', image)
        b(f'qemu-pseries+p9+{accel}', 'ppc64_guest_defconfig+clang', image)

    # GCC builds & boots
    for image in images:
        # BOOK3S64 && LITTLE_ENDIAN, PSERIES and POWERNV
        k('ppc64le_guest_defconfig+lockdep', image, merge_config=guest_configs + ['lockdep-y'])
        # BOOK3S64 && BIG_ENDIAN
        # PSERIES, POWERNV, CELL, PS3, PMAC && PMAC64, PASEMI, MAPLE
        k('ppc64_guest_defconfig+lockdep', image, merge_config=guest_configs + ['lockdep-y'])
        # G5
        k('g5_defconfig', image, merge_config=g5_configs)
        # BOOK3E_64
        k('corenet64_smp_defconfig', image, merge_config=corenet64_configs)
        k('corenet64_smp_defconfig+e6500',  image, merge_config=corenet64_configs + ['e6500-y', 'altivec-y'])
        # PPC_BOOK3S_32
        k('pmac32_defconfig', image, merge_config=pmac32_configs)
        # 44x
        k('ppc44x_defconfig', image, merge_config=['devtmpfs'])
        # 8xx
        k('mpc885_ads_defconfig', image)

        # 4K PAGE_SIZE builds, default builds are 64K
        k('ppc64le_guest_defconfig+4k', image, merge_config=guest_configs_4k)
        k('ppc64_guest_defconfig+4k', image, merge_config=guest_configs_4k)
        k('g5_defconfig+4k', image, merge_config=g5_configs + ['4k-pages'])

        # PPC_85xx
        ppc85xx_image = image
        if not image_at_least(image, ['fedora@31', 'korg@8.5.0']):
            # The 85xx builds hit gcc segfaults with earlier compilers, so use 8.5.0
            ppc85xx_image = 'korg@8.5.0'

        k('corenet32_smp_defconfig', ppc85xx_image,  merge_config=['debug-info-n'])
        b('qemu-e500mc', 'corenet32_smp_defconfig', ppc85xx_image)

        # PPC_BOOK3S_32
        b('qemu-mac99', 'pmac32_defconfig', image)
        b('qemu-mac99+debian', 'pmac32_defconfig', image)
        # 44x
        b('qemu-44x', 'ppc44x_defconfig', image)
        # ppc64e
        b('qemu-ppc64e', 'corenet64_smp_defconfig', image)
        b('qemu-ppc64e+compat', 'corenet64_smp_defconfig', image)
        b('qemu-e6500', 'corenet64_smp_defconfig+e6500', image)
        b('qemu-e6500+debian', 'corenet64_smp_defconfig+e6500', image)
        # G5
        b('qemu-g5', 'g5_defconfig', image)
        b('qemu-g5+compat', 'g5_defconfig', image)
        b('qemu-g5', 'g5_defconfig+4k', image)
        b('qemu-g5+compat', 'g5_defconfig+4k', image)

        # pseries boots
        b('qemu-pseries+p10+tcg',  'ppc64le_guest_defconfig+lockdep', image)
        b('qemu-pseries+p10+tcg',  'ppc64_guest_defconfig+lockdep',   image)
        b('qemu-pseries+p10+tcg',  'ppc64le_guest_defconfig+4k', image)

        b(f'qemu-pseries+p8+{accel}',   'ppc64le_guest_defconfig+lockdep', image)
        b(f'qemu-pseries+p9+{accel}',   'ppc64le_guest_defconfig+lockdep', image)
        b(f'qemu-pseries+p8+{accel}',   'ppc64_guest_defconfig+lockdep',   image)
        b(f'qemu-pseries+p9+{accel}',   'ppc64_guest_defconfig+lockdep',   image)
        b(f'qemu-pseries+p9+{accel}+fedora39', 'ppc64le_guest_defconfig+lockdep', image)
        b(f'qemu-pseries+p9+{accel}+fedora39', 'ppc64le_guest_defconfig+4k', image)

        # powernv boots
        b('qemu-powernv+p8+tcg',       'ppc64le_guest_defconfig+lockdep', image)
        b('qemu-powernv+p9+tcg',       'ppc64le_guest_defconfig+lockdep', image)
        b('qemu-powernv+p10+tcg',      'ppc64le_guest_defconfig+lockdep', image)
        b('qemu-powernv+p8+tcg',       'ppc64_guest_defconfig+lockdep',   image)
        b('qemu-powernv+p9+tcg',       'ppc64_guest_defconfig+lockdep',   image)
        b('qemu-powernv+p10+tcg',      'ppc64_guest_defconfig+lockdep',   image)
        b('qemu-powernv+p10+tcg',      'ppc64_guest_defconfig+4k',        image)


    for image in ['ubuntu@16.04', 'ubuntu']:
        suite.add_selftest(image, 'ppc64le')
        suite.add_selftest(image, 'ppc64le', 'ppctests')

    return suite


def full_compile_test(args, suite=None):
    images = std_images(args)
    if suite is None:
        suite = TestSuite('full-compile-test')

    k = suite.add_kernel

    ######################################### 
    # Clang builds
    ######################################### 
    image = clang_image(images)
    if image:
        k('ppc64le_guest_defconfig+clang', image, merge_config=guest_configs, clang=True)
        k('ppc64le_guest_defconfig+clang+ias', image, merge_config=guest_configs, clang=True, llvm_ias=True)
        k('ppc64_guest_defconfig+clang', image, merge_config=guest_configs, clang=True)
        k('corenet64_smp_defconfig+clang', image, merge_config=corenet64_configs + ['disable-werror'], clang=True)
        k('corenet32_smp_defconfig+clang', image, merge_config=['debug-info-n', 'ppc64e-qemu', 'disable-werror'], clang=True)
        k('pmac32_defconfig+clang', image, merge_config=pmac32_configs + ['disable-werror'], clang=True)
        k('g5_defconfig+clang', image, merge_config=g5_configs + ['disable-werror'], clang=True)
        k('mpc885_ads_defconfig+clang', image, clang=True)
        k('ppc44x_defconfig+clang', image, clang=True)

    ######################################### 
    # Sparse builds
    ######################################### 
    image = sparse_image(images)
    if image:
        k('ppc64le_defconfig+sparse', image, sparse=True)
        k('ppc64_defconfig+sparse', image, sparse=True)
        k('pmac32_defconfig+sparse', image, sparse=True)

    # MICROWATT, also VSX=n, doesn't build with GCC 5.5.0
    k('microwatt_defconfig', 'fedora')

    # GCC builds & boots
    for image in images:
        ######################################### 
        # Major platforms coverage
        ######################################### 
        # BOOK3S64 && LITTLE_ENDIAN, PSERIES and POWERNV
        k('ppc64le_guest_defconfig', image, merge_config=guest_configs)
        # BOOK3S64 && BIG_ENDIAN
        # PSERIES, POWERNV, CELL, PS3, PMAC && PMAC64, PASEMI, MAPLE
        k('ppc64_guest_defconfig', image, merge_config=guest_configs)
        # PMAC && PMAC64
        k('g5_defconfig', image, merge_config=g5_configs)
        # BOOK3E_64
        k('corenet64_smp_defconfig', image, merge_config=corenet64_configs)

        ppc85xx_image = image
        if not image_at_least(image, ['fedora@31', 'korg@8.5.0']):
            # The 85xx builds hit gcc segfaults with earlier compilers, so use 8.5.0
            ppc85xx_image = 'korg@8.5.0'

        # PPC_85xx, PPC_E500MC
        k('corenet32_smp_defconfig', ppc85xx_image, merge_config=['debug-info-n'])
        # PPC_85xx, SMP=y, PPC_E500MC=n
        k('mpc85xx_smp_defconfig', ppc85xx_image)
        # PPC_85xx, SMP=n
        k('mpc85xx_defconfig', ppc85xx_image)
        # PPC_85xx + RANDOMIZE_BASE
        k('mpc85xx_smp_defconfig+kaslr', ppc85xx_image, merge_config=['randomize-base-y'])

        # PPC_BOOK3S_32
        k('pmac32_defconfig', image, merge_config=pmac32_configs)
        k('pmac32_defconfig+smp', image, merge_config=pmac32_configs + ['smp-y'])
        # 44x
        k('ppc44x_defconfig', image, merge_config=['devtmpfs'])
        # 8xx
        k('mpc885_ads_defconfig', image)

        ######################################### 
        # allyes/no/mod
        ######################################### 
        if image.startswith('korg@'):
            no_gcc_plugins = ['gcc-plugins-n']
        else:
            no_gcc_plugins = []

        # 32-bit Book3S BE
        k('allnoconfig', image)
        # 64-bit Book3S LE
        # Doesn't exist
        #k('ppc64le_allyesconfig', image)

        allyesmod_image = image
        if not image_at_least(image, ['fedora@31', 'korg@8.5.0']):
            # GCC 5.5.0 fails on various things for allyes/allmod
            allyesmod_image = 'korg@8.5.0'

        # 64-bit Book3S BE
        k('allyesconfig', allyesmod_image, merge_config=no_gcc_plugins)
        # 64-bit Book3S BE
        k('allmodconfig', allyesmod_image, merge_config=no_gcc_plugins)
        # 64-bit Book3S LE
        k('ppc64le_allmodconfig', allyesmod_image, merge_config=no_gcc_plugins)
        # 32-bit Book3S BE (korg 5.5.0 doesn't build)
        k('ppc32_allmodconfig', allyesmod_image, merge_config=no_gcc_plugins)
        # 64-bit BOOK3E BE (korg 5.5.0 doesn't build)
        # FIXME Broken due to start_text_address problems
        # k('ppc64_book3e_allmodconfig', allyesmod_image, merge_config=no_gcc_plugins)

        ######################################### 
        # specific machine/platform configs
        ######################################### 
        # PSERIES (BE)
        k('pseries_defconfig', image),  
        # PSERIES (LE)
        k('pseries_le_defconfig', image),  
        # Options for old LPARs
        k('ppc64le_guest_defconfig+legacy', image, merge_config=legacy_guest_configs)
        # POWERNV
        cfgs = powernv_configs
        if image == 'korg@5.5.0':
            # BTF causes build errors with 5.5.0, disable it
            cfgs.append('btf-n')
        k('powernv_defconfig', image, merge_config=cfgs)
        # CELL
        k('cell_defconfig', image, merge_config=cell_configs)
        k('ps3_defconfig', image)
        # POWERNV, some shrinking/hardening options
        k('skiroot_defconfig', image)
        # PPC_86xx (BOOK3S_32)
        k('mpc86xx_smp_defconfig', image)

        ######################################### 
        # specific features
        ######################################### 
        # PPC_8xx + PPC16K_PAGES
        k('mpc885_ads_defconfig+16k', image, merge_config=['16k-pages'])

        # 4K PAGE_SIZE builds, default builds are 64K
        k('ppc64le_guest_defconfig+4k', image, merge_config=guest_configs_4k)
        k('ppc64_guest_defconfig+4k', image, merge_config=guest_configs_4k)
        k('g5_defconfig+4k', image, merge_config=g5_configs + ['4k-pages'])

        ######################################### 
        # specific enabled features
        ######################################### 
        for feature in ['preempt', 'compat', 'lockdep', 'reltest', 'opt-for-size']:
            k(f'ppc64_defconfig+{feature}',   image, merge_config=[f'{feature}-y'])
            k(f'ppc64le_defconfig+{feature}', image, merge_config=[f'{feature}-y'])

        pcrel_image = image
        if not image_at_least(image, ['fedora@36', 'korg@12.1.0']):
            # Only GCC >= 12 can build pcrel because it needs -mcpu=power10
            pcrel_image = 'korg@12.1.0'

        k('ppc64le_defconfig+pcrel', pcrel_image, merge_config=['pcrel-y'])
        # FIXME doesn't build
        # k('ppc64_defconfig+pcrel',   pcrel_image, merge_config=['pcrel-y'])

        ######################################### 
        # specific disabled features
        ######################################### 
        for feature in ['radix', 'hpt-mmu']:
            feat_image = image
            if feature == 'hpt-mmu' and not image_at_least(image, ['fedora@36', 'korg@12.1.0']):
                # Only GCC >= 12 can build HPT=n because it needs -mcpu=power10
                feat_image = 'korg@12.1.0'
            
            k(f'ppc64_defconfig+no{feature}',   feat_image, merge_config=[f'{feature}-n'])
            k(f'ppc64le_defconfig+no{feature}', feat_image, merge_config=[f'{feature}-n'])
            k(f'ppc64_defconfig+no{feature}+4k',   feat_image, merge_config=[f'{feature}-n', '4k-pages'])
            k(f'ppc64le_defconfig+no{feature}+4k', feat_image, merge_config=[f'{feature}-n', '4k-pages'])

        k('ppc64_defconfig+noelf-abi-v2',   image, merge_config=['elf-abi-v2-n'])

        for feature in ['modules']:
            k(f'ppc64_defconfig+no{feature}',   image, merge_config=[f'{feature}-n'])
            k(f'ppc64le_defconfig+no{feature}', image, merge_config=[f'{feature}-n'])

    ######################################### 
    # selftests
    ######################################### 
    for version in ['16.04', '18.04', '20.04', '22.04', '22.10']:
        image = f'ubuntu@{version}'
        for subarch in ['ppc64', 'ppc64le']:
            suite.add_selftest(image, subarch, 'selftests')
            suite.add_selftest(image, subarch, 'ppctests')

    return suite


def full_compile_and_qemu(args):
    suite = TestSuite('full-compile-and-qemu', qemus=args.qemus)
    full_compile_test(args, suite)
    qemu_coverage(args, suite)
    return suite


def qemu_kasan(args, suite=None):
    images = std_images(args)
    if suite is None:
        suite = TestSuite('qemu-kasan', qemus=args.qemus)

    k = suite.add_kernel
    b = suite.add_qemu_boot

    for image in images:
        k('ppc64le_guest_defconfig',  image, merge_config=guest_configs + ['kasan-y'])

        # Just a plain boot
        b('qemu-pseries+p9+kvm+radix+fedora34', 'ppc64le_guest_defconfig', image,
          script='qemu-pseries+p9+kvm+fedora34')
        b('qemu-pseries+p9+kvm+hpt+fedora34', 'ppc64le_guest_defconfig', image,
          script='qemu-pseries+p9+kvm+fedora34', cmdline='disable_radix')

        # Now boot and test KASAN
        test = QemuTestConfig('kasan-kunit', ['kasan_kunit'])
        b('qemu-pseries+p9+kvm+radix+fedora34+kasan', 'ppc64le_guest_defconfig', image,
          script='qemu-pseries+p9+kvm+fedora34', tests=[test])
        # FIXME currently broken - some missing kasan_arch_is_ready() or similar
        #b('qemu-pseries+p9+kvm+hpt+fedora34+kasan', 'ppc64le_guest_defconfig', image,
        #  script='qemu-pseries+p9+kvm+fedora34', tests=[test], cmdline='disable_radix')

    return suite


def qemu_selftests(args):
    suite = TestSuite('qemu-selftests')
    k = suite.add_kernel
    b = suite.add_qemu_boot

    image = 'fedora'

    for arch in ['ppc64', 'ppc64le']:
        k(f'{arch}_guest_defconfig',  image, merge_config=guest_configs)
        selftests = suite.add_selftest('ubuntu@20.04', arch)

        exclude = []
        # Not clear what causes failure
        exclude.append('powerpc/pmu/ebb:instruction_count_test')
        exclude.append('powerpc/pmu/ebb:fork_cleanup_test')
        # Confused by qemu
        exclude.append('powerpc/security:rfi_flush')
        exclude.append('powerpc/security:entry_flush')
        exclude.append('powerpc/security:uaccess_flush')
        exclude.append('powerpc/security:spectre_v2')
        # Slow and not that useful for bug finding
        exclude.append('powerpc/benchmarks:context_switch')
        exclude.append('powerpc/benchmarks:fork')
        exclude.append('powerpc/benchmarks:futex_bench')
        exclude.append('powerpc/benchmarks:mmap_bench')
        # Tends to timeout
        exclude.append('powerpc/signal:sigfuz')
        # Requires certain hardware
        exclude.append('powerpc/eeh:eeh-basic.sh')

        if arch == 'ppc64le':
            tests = [QemuSelftestsConfig(selftests, 'powerpc.*', exclude=exclude)]
            name = 'qemu-pseries+p9+kvm+fedora41'
            b(name, f'{arch}_guest_defconfig', image, tests=tests)
        else:
            # 64-bit tests don't work due to missing libraries
            exclude.append('powerpc/stringloops:.*')
            exclude.append('powerpc/copyloops:.*')
            exclude.append('powerpc/tm:.*')
            exclude.append('powerpc/pmu.*')
            exclude.append('powerpc/mm:.*')
            exclude.append('powerpc/math:.*')
            exclude.append('powerpc/ptrace:.*')
            exclude.append('powerpc/papr_sysparm:papr_sysparm')
            exclude.append('powerpc/switch_endian:switch_endian_test')
            exclude.append('powerpc/vphn:test-vphn')
            tests = [QemuSelftestsConfig(selftests, 'powerpc.*', exclude=exclude)]
            name = 'qemu-pseries+p9+kvm+be+debian'
            b(name, f'{arch}_guest_defconfig', image, tests=tests)

    return suite


def std_boot(args, hostname, defconfig, merge_configs, suite=None):
    images = args.images
    if not images:
        images = [DEFAULT_NEW_IMAGE]

    if suite is None:
        suite = TestSuite(hostname)

    for image in images:
        suite.add_kernel(defconfig, image, merge_config=merge_configs)
        suite.add_boot(hostname, defconfig, image)

    return suite


def std_boot_and_test(args, hostname, defconfig, merge_configs, suite=None):
    images = args.images
    if not images:
        images = [DEFAULT_NEW_IMAGE]

    if suite is None:
        suite = TestSuite(hostname)

    ppctests = suite.add_selftest('ubuntu@24.04', 'ppc64le', 'ppctests')

    exclude = []
    # Tends to timeout
    exclude.append('powerpc/signal:sigfuz')
    # Requires certain hardware
    exclude.append('powerpc/eeh:eeh-basic.sh')
    # Not always reliable depending on firmware settings etc.
    exclude.append('powerpc/security:spectre_v2')
    # Flakey
    exclude.append('powerpc/pmu:count_stcx_fail')

    tests = [SelftestsConfig(ppctests, 'powerpc', exclude)]

    for image in images:
        suite.add_kernel(defconfig, image, merge_config=merge_configs)
        suite.add_boot(hostname, defconfig, image, tests=tests)

    return suite


def ltcppm1(args, suite=None):
    return std_boot(args, 'ltcppm1.aus.stglabs.ibm.com', 'powernv_defconfig', powernv_configs,  suite)

def ltcppm2(args, suite=None):
    return std_boot(args, 'ltcppm2.aus.stglabs.ibm.com', 'ppc64le_guest_config', guest_configs,  suite)

def ltcppm3(args, suite=None):
    return std_boot_and_test(args, 'ltcppm3.aus.stglabs.ibm.com', 'powernv_defconfig', powernv_configs, suite)


def ppm_hw_boots(args):
    suite = TestSuite('ppm-hw-boots')
    ltcppm1(args, suite)
    ltcppm2(args, suite)
    ltcppm3(args, suite)
    return suite


def t4240rdb(args, suite=None):
    images = args.images
    if not images:
        images = [DEFAULT_NEW_IMAGE]

    if suite is None:
        suite = TestSuite('t4240rdb')

    for image in images:
        suite.add_kernel('corenet64_smp_defconfig+e6500',  image, merge_config=corenet64_configs + ['e6500-y', 'altivec-y'])
        suite.add_boot('t4240rdb', 'corenet64_smp_defconfig+e6500', image)

    # XXX Can't run selftests because Void userspace is BE ELFv2
    # Need to build the tests with a matching toolchain.

    return suite


def didgo5(args, suite=None):
    return std_boot(args, 'didgo5', 'ppc64_guest_defconfig+legacy', legacy_guest_configs, suite)


def mpe_g5(args, suite=None):
    return std_boot(args, 'mpe-g5', 'g5_defconfig', g5_configs, suite)


def spork(args, suite=None):
    return std_boot_and_test(args, 'spork', 'powernv_defconfig', powernv_configs, suite)


def oz_hw_boots(args):
    suite = TestSuite('oz-hw-boots')
    t4240rdb(args, suite)
    didgo5(args, suite)
    mpe_g5(args, suite)
    spork(args, suite)
    return suite
