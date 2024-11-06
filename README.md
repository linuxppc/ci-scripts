linuxppc CI scripts
===================

Scripts I use to do continuous integration for linuxppc.

Still (and probably always) under heavy development.

> [!NOTE]
> The scripts notionally work with `docker` or `podman`, but they're only regularly tested with `podman` on Fedora.

Quick start
-----------

Make sure you can run containers.

On Fedora the scripts will use `podman`, on Ubuntu they use `docker`, 

You need a Linux source tree, which hasn't been built in. You can make sure it's
clean with `make mrproper`, or clone a fresh tree.

Clone this repo. The examples use `~/ci-scripts` for brevity, but the repo can be located anywhere.

```
$ cd ci-scripts
$ cd build
$ make pull-image@ppc64le@fedora
$ make SRC=~/src/linux kernel@ppc64le@fedora JFACTOR=$(nproc)
```

This will build you a `ppc64le_defconfig` using the latest Fedora toolchain.

The kernel will be in `~/ci/scripts/build/output/latest-kernel/vmlinux`.

For more help try `make help`.

Building different defconfigs
-----------------------------

You can specify a defconfig with `DEFCONFIG`.

```
$ make SRC=~/src/linux kernel@ppc64le@fedora DEFCONFIG=powernv_defconfig JFACTOR=$(nproc)
```

Note that the subarch (eg. `ppc64le`) needs to match the defconfig, so to build
`ppc64_defconfig`, use `ppc64`.

```
$ make SRC=~/src/linux kernel@ppc64@fedora DEFCONFIG=ppc64_defconfig JFACTOR=$(nproc)
```

Different toolchains
--------------------

There are images for various toolchains, they are encoded in the distro name/version.

 - `korg@14.2.0`: kernel.org gcc 14.2.0, binutils 2.42
 - `korg@14.1.0`: kernel.org gcc 14.1.0, binutils 2.42
 - `korg@13.3.0`: kernel.org gcc 13.1.0, binutils 2.42
 - `korg@13.2.0`: kernel.org gcc 13.1.0, binutils 2.41
 - `korg@13.1.0`: kernel.org gcc 13.1.0, binutils 2.40
 - `korg@12.4.0`: kernel.org gcc 12.3.0, binutils 2.42
 - `korg@12.3.0`: kernel.org gcc 12.3.0, binutils 2.40
 - `korg@12.2.0`: kernel.org gcc 12.2.0, binutils 2.39
 - `korg@12.1.0`: kernel.org gcc 12.1.0, binutils 2.38
 - `korg@11.3.0`: kernel.org gcc 11.3.0, binutils 2.38
 - `korg@11.1.0`: kernel.org gcc 11.1.0, binutils 2.36.1
 - `korg@10.3.0`: kernel.org gcc 10.3.0, binutils 2.36.1
 - `korg@9.4.0`: kernel.org gcc 9.4.0, binutils 2.36.1
 - `korg@9.3.0`: kernel.org gcc 9.3.0, binutils 2.34
 - `korg@8.5.0`: kernel.org gcc 8.5.0, binutils 2.36.1
 - `korg@8.1.0`: kernel.org gcc 8.1.0, binutils 2.30
 - `korg@5.5.0`: kernel.org gcc 5.5.0, binutils 2.29.1
 - `ubuntu@24.04`: Ubuntu 24.04, gcc 13.2.0, binutils 2.42
 - `ubuntu@22.04`: Ubuntu 22.04, gcc 11.2.0, binutils 2.38
 - `ubuntu@21.10`: Ubuntu 21.10, gcc 11.2.0, binutils 2.37
 - `ubuntu@21.04`: Ubuntu 21.04, gcc 10.3.0, binutils 2.36.1
 - `ubuntu@20.04`: Ubuntu 20.04, gcc 9.4.0, binutils 2.34
 - `ubuntu@18.04`: Ubuntu 18.04, gcc 7.5.0, binutils 2.30
 - `ubuntu@16.04`: Ubuntu 16.04, gcc 5.4.0, binutils 2.26.1
 - `fedora@40`: Fedora 40, gcc 14.0.1, binutils 2.41-34, clang 18.1.1
 - `fedora@39`: Fedora 39, gcc 13.2.1, binutils 2.40-14, clang 17.0.6
 - `fedora@38`: Fedora 38, gcc 12.2.1, binutils 2.39-3, clang 16.0.2
 - `fedora@37`: Fedora 37, gcc 12.2.1, binutils 2.38-5, clang 15.0.7
 - `fedora@36`: Fedora 36, gcc 12.1.1, binutils 2.37-7, clang 14.0.5
 - `fedora@35`: Fedora 35, gcc 11.2.1, binutils 2.37-3, clang 13.0.1
 - `fedora@34`: Fedora 34, gcc 11.2.1, binutils 2.35.2, clang 12.0.1
 - `fedora@33`: Fedora 33, gcc 10.2.1, binutils 2.35.1, clang 11.0.0
 - `fedora@31`: Fedora 31, gcc 9.2.1, binutils 2.32, clang 9.0.1
 
Only the Ubuntu toolchains can build the selftests.

Building selftests
------------------

To build the kernel selftests:

```
$ make SRC=~/src/linux selftests@ppc64le@ubuntu JFACTOR=$(nproc)
```

Or just the powerpc selftests:

```
$ make SRC=~/src/linux ppctests@ppc64le@ubuntu JFACTOR=$(nproc)
```

You can also build the powerpc selftests with all available toolchains using:

```
$ make SRC=~/src/linux ppctests JFACTOR=$(nproc)
```

Other options
-------------

As mentioned above you pass the make -j factor with `JFACTOR=n`.

To run sparse use the `fedora` image and pass `SPARSE=2`.

```
$ make SRC=~/src/linux kernel@ppc64le@fedora SPARSE=2 JFACTOR=$(nproc)
```

The log will be in eg. `~/ci-scripts/build/output/latest-kernel/sparse.log`.

To only run sparse on files being recompiled, pass `SPARSE=1`.

To build modules pass `MODULES=1`

To convert all modules to builtin, pass `MOD2YES=1`.

To build with clang pass `CLANG=1`, only works using the latest Fedora or Ubuntu image.

For a quiet build pass `QUIET=1`, for verbose pass `VERBOSE=1`.

By default the script does an incremental build, ie. it doesn't clean. You can
clean before building by passing `PRE_CLEAN=1`, or afterward with `POST_CLEAN=1`.

Alternately you can clean everything with `make clean`.

Multiple builds
---------------

If you have enough CPU and disk space, you can run multiple builds at once. The
output directory is namespaced based on the subarch, distro, version, and
defconfig.

Building your own image
-----------------------

If you don't want to pull an untrusted image, you can build it yourself with:

```
$ make rebuild-image@ppc64le@fedora
```

Note that the build mounts the source tree read-only, so nothing it does can
affect your source tree.

Bisecting the kernel vs a selftest
----------------------------------

Build the selftests using a version of the test that's known good. Usually
there's no reason to rebuild the tests on every kernel revision.

These examples are run from the kernel directory, not the ci-scripts directory.
It can be done either way, but it's more natural to run from the kernel
directory when bisectting the kernel. This assumes Linux is in `~/linux` and
these scripts are in `~/ci-scripts`, adapt as appropriate.

```
$ cd ~/linux
```

```
$ make SRC=$PWD -C ~/ci-scripts/build QUIET=1 JFACTOR=$(nproc) ppctests@ppc64le@ubuntu@22.04 INSTALL=1
```

> [!NOTE]
> :rotating_light: Building the selftests with Ubuntu 22.04 uses glibc 2.35.
> The default rootdisk uses glibc 2.36, so there should be no issue with missing
> symbols in glibc. If using another root disk you may need to build with an older
> Ubuntu image. Another option is to build the selftests statically.

Tar up the selftests into the current directory, the qemu scripts will detect them:

```
$ tar -czf selftests.tar.gz -C $HOME/ci-scripts/build/output/latest-selftests/ install
```

```
$ ~/ci-scripts/scripts/boot/qemu-pseries+kvm --callback "run_selftests(powerpc/mm:wild_bctr)"
...
INFO: Running 'qemu-system-ppc64 -nographic -vga none -M pseries -smp 8 -m 4G -accel kvm ...
...
/ # INFO: Running individual selftests powerpc/mm:wild_bctr
/var/tmp/selftests/run_kselftest.sh -t powerpc/mm:wild_bctr
[    2.783761][  T201] kselftest: Running tests in powerpc
TAP version 13
1..1
# timeout set to 300
# selftests: powerpc/mm: wild_bctr
# test: wild_bctr
# tags: git_version:v6.8-rc6-2555-gfe559db
# Everything is OK in here.
...
# success: wild_bctr
ok 1 selftests: powerpc/mm: wild_bctr
/ # poweroff
/ # Stopping network: [    3.104385][  T274] ip (274) used greatest stack depth: 10912 bytes left
OK
Saving random seed: OK
Stopping klogd: OK
Stopping syslogd: OK
umount: devtmpfs busy - remounted read-only
umount: can't unmount /: Invalid argument
The system is going down NOW!
Sent SIGTERM to all processes
Sent SIGKILL to all processes
Requesting system poweroff
[    5.152672][  T293] reboot: Power down
INFO: Test completed OK
```

More than one selftest can be run by passing multiple arguments to
`run_selftests` or by passing multiple `--callback` options.

From there the bisection can either be run by hand, or fully automated by
creating a script to build the kernel and run the qemu test.

Using the powerpc debian image
------------------------------

The debian powerpc image in `root-disks` can be used to test big endian kernels.
It also exercises COMPAT, which is not tested on ppc64le these days.

The kernel needs virtio drivers as well as 9PFS built-in. For example to get it
booting with `g5_defconfig`:

```
$ cd linux
$ ~/ci-scripts/scripts/misc/apply-configs.py 9p guest_configs cgroups-y
$ make g5_defconfig vmlinux
$ ~/ci-scripts/boot/qemu-g5+debian
```

To do interactive testing, run the boot script with `--interactive`, the login
is `root/linuxppc`.

Once logged in, to install packages a few steps are needed.

If the network doesn't come up by default:
```
dhclient $(basename $(ls -1d /sys/class/net/en*))
```

If you need to use a http proxy:
```
echo 'Acquire::http::Proxy "http://proxy.org:3128";' > /etc/apt/apt.conf.d/00proxy
```

Tell apt to update package lists while ignoring missing GPG keys:
```
apt -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowDowngradeToInsecureRepositories=true update
```

At that point you should be able to install the updated keyring:
```
apt install -y --allow-unauthenticated debian-ports-archive-keyring
```

And update package lists again:
```
apt update
```

Then you should be able to install packages, eg:
```
apt install gcc
```

If you still can't install packages due to GPG errors, you can disable package authentication with:
```
echo 'APT::Get::AllowUnauthenticated "true";' > /etc/apt/apt.conf.d/00allow-unauth
```
