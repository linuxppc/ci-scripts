# Shared config fragments etc.

guest_configs = [
    'arch/powerpc/configs/guest.config',
    'netconsole-n',
    'ibmveth',               # For PowerVM LPARs
    'kuap',
    'criu',                  # For seccomp tests
    'user-ns',               # For seccomp tests
    'lkdtm',                 # Because it's useful
    'ptdump',                # Because it's useful
    'strict-rwx',            # Get some test coverage
    'kfence',
    'srr-debug',
    'irq-soft-mask-debug',
    'printk-index',
    'debug-atomic-sleep',
    'secure-boot',
    'debug-vm',
    'btrfs-y',               # Needed for F39
    'vfat-y',                # Needed for F39
    'zram',                  # Needed for F39
]

guest_configs_4k = guest_configs + ['4k-pages']
guest_configs_maxsmp = guest_configs + ['nr-cpus-8192']

legacy_guest_configs = [
    'arch/powerpc/configs/guest.config',
    'netconsole-n',
    'ibmveth',         # For PowerVM LPARs
    'ibmehea',         # Needed for Power7
    'strict-rwx-off',  # Bloats image too much for netboot to work w/128MB RMA
    'nr-cpus-64',      # Shrink kernel size
    'ftrace-n',        # Shrink kernel size
]

pmac32_configs = [
    'pmaczilog',
    'devtmpfs',
    'debugfs',
    'ptdump',
    'debug-atomic-sleep',
    'cgroups-y',
    'arch/powerpc/configs/guest.config',
]

g5_configs = [
    'pmaczilog',
    'debugfs',
    'ptdump',
    'pstore',
    'kvm-pr-y',
    'agp-uninorth-y',
]

cell_configs = [
    'cell',
    'lockdep-y',
    'debug-atomic-sleep',
    'xmon-non-default',
]

powernv_configs = [
    'tools/testing/selftests/ftrace/config',
    'tools/testing/selftests/bpf/config',
    'criu',             # needed for selftests-seccomp
    'igb',              # Needed on some machines
    'xfs-y',            # Needed on some machines
    'bridge-y',         # Needed on some machines
    'ahci-y',           # Needed on some machines
    'i40e-y',           # Needed on some machines
    'kvm-pr-m',
    'strict-rwx',
    'debug-atomic-sleep',
    'selftests',
    'pci-iov',
    'page-poisoning-y',
    'srr-debug',        # Get some test coverage
    'livepatch',
    'secure-boot',
    'zram',
    'ptdump',
    'amdgpu-y',
    'drm-aspeed-y',     # Aspeed DRM driver for /dev/fb0 on powernv machines
    'fb-y',             # Enable frame buffer for /dev/fb0 & alignment test
    'xmon-non-default', # Better oopses in logs
    'xmon-rw',
    'selinux',          # Avoid selinux relabeling on Fedora machines
    'vfio-y',           # Test coverage of VFIO
    'cgroups-y',        # So podman can run
    'gup-test-y',       # Enable selftest
]

powernv_lockdep_configs = powernv_configs + ['lockdep-y']

corenet64_configs = [
    'debug-info-n',
    'ppc64e-qemu',
    'arch/powerpc/configs/guest.config',
]
