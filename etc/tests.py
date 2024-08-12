from ngci import TestSuite, SelftestsBuild, SelftestsConfig, QemuSelftestsConfig, TestConfig, QemuNetTestConfig
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
        # As above with 4K page size
        k('ppc64le_guest_defconfig+4k', image, merge_config=guest_configs_4k)
        k('ppc64_guest_defconfig+4k', image, merge_config=guest_configs_4k)
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

        # PPC_85xx
        if image != "korg@5.5.0":
            k('corenet32_smp_defconfig', image, merge_config=['debug-info-n'])
            b('qemu-e500mc', 'corenet32_smp_defconfig', image)

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
        # pseries boots
        b('qemu-pseries+p10+tcg',  'ppc64le_guest_defconfig+lockdep', image)
        b('qemu-pseries+p10+tcg',  'ppc64_guest_defconfig+lockdep',   image)

        b(f'qemu-pseries+p8+{accel}',   'ppc64le_guest_defconfig+lockdep', image)
        b(f'qemu-pseries+p9+{accel}',   'ppc64le_guest_defconfig+lockdep', image)
        b(f'qemu-pseries+p8+{accel}',   'ppc64_guest_defconfig+lockdep',   image)
        b(f'qemu-pseries+p9+{accel}',   'ppc64_guest_defconfig+lockdep',   image)
        b(f'qemu-pseries+p9+{accel}+fedora39', 'ppc64le_guest_defconfig+lockdep', image)
        # powernv boots
        b('qemu-powernv+p8+tcg',       'ppc64le_guest_defconfig+lockdep', image)
        b('qemu-powernv+p9+tcg',       'ppc64le_guest_defconfig+lockdep', image)
        b('qemu-powernv+p10+tcg',      'ppc64le_guest_defconfig+lockdep', image)
        b('qemu-powernv+p8+tcg',       'ppc64_guest_defconfig+lockdep',   image)
        b('qemu-powernv+p9+tcg',       'ppc64_guest_defconfig+lockdep',   image)
        b('qemu-powernv+p10+tcg',      'ppc64_guest_defconfig+lockdep',   image)


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
        # As above with 4K page size
        k('ppc64le_guest_defconfig+4k', image, merge_config=guest_configs_4k)
        k('ppc64_guest_defconfig+4k', image, merge_config=guest_configs_4k)
        # PMAC && PMAC64
        k('g5_defconfig', image, merge_config=g5_configs)
        # BOOK3E_64
        k('corenet64_smp_defconfig', image, merge_config=corenet64_configs)
        # PPC_85xx, PPC_E500MC
        k('corenet32_smp_defconfig', image, merge_config=['debug-info-n'])
        # PPC_85xx, SMP=y, PPC_E500MC=n
        k('mpc85xx_smp_defconfig', image)
        # PPC_85xx, SMP=n
        k('mpc85xx_defconfig', image)
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

        # GCC 5.5.0 fails on various things for allyes/allmod
        tmp_image = image.replace('korg@5.5.0', 'korg@8.5.0')
        # 64-bit Book3S BE
        k('allyesconfig', tmp_image, merge_config=no_gcc_plugins)
        # 64-bit Book3S BE
        k('allmodconfig', tmp_image, merge_config=no_gcc_plugins)
        # 64-bit Book3S LE
        k('ppc64le_allmodconfig', tmp_image, merge_config=no_gcc_plugins)
        # 32-bit Book3S BE (korg 5.5.0 doesn't build)
        k('ppc32_allmodconfig', tmp_image, merge_config=no_gcc_plugins)
        # 64-bit BOOK3E BE (korg 5.5.0 doesn't build)
        # FIXME Broken due to start_text_address problems
        # k('ppc64_book3e_allmodconfig', tmp_image, merge_config=no_gcc_plugins)

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
        # POWERNV, some shrinking/hardening options
        k('skiroot_defconfig', image)
        # PPC_86xx (BOOK3S_32)
        k('mpc86xx_smp_defconfig', image)

        ######################################### 
        # specific features
        ######################################### 
        # PPC_8xx + PPC16K_PAGES
        k('mpc885_ads_defconfig+16k', image, merge_config=['16k-pages'])

        ######################################### 
        # specific enabled features
        ######################################### 
        for feature in ['preempt', 'compat', 'lockdep', 'reltest']:
            k(f'ppc64_defconfig+{feature}',   image, merge_config=[f'{feature}-y'])
            k(f'ppc64le_defconfig+{feature}', image, merge_config=[f'{feature}-y'])

        ######################################### 
        # specific disabled features
        ######################################### 
        for feature in ['radix', 'modules']:
            k(f'ppc64_defconfig+no{feature}',   image, merge_config=[f'{feature}-n'])
            k(f'ppc64le_defconfig+no{feature}', image, merge_config=[f'{feature}-n'])

        # PPC_85xx + RANDOMIZE_BASE
        # This hits gcc segfaults with earlier compilers, so use 8.5.0
        k('mpc85xx_smp_defconfig+kaslr', image.replace('korg@5.5.0', 'korg@8.5.0'), merge_config=['randomize-base-y'])

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
