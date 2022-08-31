linuxppc CI scripts
===================

Scripts I use to do continuous integration for linuxppc.

Still (and probably always) under heavy development.

Quick start
-----------

Make sure you can run containers.

On Ubuntu the scripts will use `docker`, on Fedora they will use `podman`.

You need a Linux source tree, which hasn't been built in. You can make sure it's
clean with `make mrproper`, or clone a fresh tree.

Clone this repo.

```
$ cd ci-scripts
$ cd build
$ make pull-image@ppc64le@ubuntu
$ make SRC=~/src/linux kernel@ppc64le@ubuntu JFACTOR=$(nproc)
```

This will build you a `ppc64le_defconfig` using the latest Ubuntu toolchain.

The kernel will be in `output/ppc64le@ubuntu/ppc64le_defconfig/vmlinux`.

For more help try `make help`.

Building different defconfigs
-----------------------------

You can specify a defconfig with `DEFCONFIG`.

```
$ make SRC=~/src/linux kernel@ppc64le@ubuntu DEFCONFIG=powernv_defconfig JFACTOR=$(nproc)
```

Note that the subarch (eg. `ppc64le`) needs to match the defconfig, so to build
`ppc64_defconfig`, use `ppc64`.

```
$ make SRC=~/src/linux kernel@ppc64@ubuntu DEFCONFIG=ppc64_defconfig JFACTOR=$(nproc)
```

Different toolchains
--------------------

There are images for various toolchains, they are encoded in the distro name/version.

 - `korg@12.1.0`: kernel.org gcc 12.1.0, binutils 2.38
 - `korg@11.3.0`: kernel.org gcc 11.3.0, binutils 2.38
 - `korg@11.1.0`: kernel.org gcc 11.1.0, binutils 2.36.1
 - `korg@10.3.0`: kernel.org gcc 10.3.0, binutils 2.36.1
 - `korg@9.4.0`: kernel.org gcc 9.4.0, binutils 2.36.1
 - `korg@9.3.0`: kernel.org gcc 9.3.0, binutils 2.34
 - `korg@8.5.0`: kernel.org gcc 8.5.0, binutils 2.36.1
 - `korg@8.1.0`: kernel.org gcc 8.1.0, binutils 2.30
 - `korg@5.5.0`: kernel.org gcc 5.5.0, binutils 2.29.1
 - `ubuntu@22.04`: Ubuntu 22.04, gcc 11.2.0, binutils 2.38
 - `ubuntu@21.10`: Ubuntu 21.10, gcc 11.2.0, binutils 2.37
 - `ubuntu@21.04`: Ubuntu 21.04, gcc 10.3.0, binutils 2.36.1
 - `ubuntu@20.04`: Ubuntu 20.04, gcc 9.4.0, binutils 2.34
 - `ubuntu@18.04`: Ubuntu 18.04, gcc 7.5.0, binutils 2.30
 - `ubuntu@16.04`: Ubuntu 16.04, gcc 5.4.0, binutils 2.26.1
 - `fedora@36`: Fedora 36, gcc 12.1.1, binutils 2.37-7
 - `fedora@35`: Fedora 35, gcc 11.2.1, binutils 2.37-3
 - `fedora@34`: Fedora 34, gcc 11.2.1, binutils 2.35.2
 - `fedora@33`: Fedora 33, gcc 10.2.1, binutils 2.35.1
 - `fedora@31`: Fedora 31, gcc 9.2.1, binutils 2.32
 
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

To run sparse use the `ubuntu` image and pass `SPARSE=2`.

```
$ make SRC=~/src/linux kernel@ppc64le@ubuntu SPARSE=2 JFACTOR=$(nproc)
```

The log will be in eg. `output/ppc64le@ubuntu/ppc64le_defconfig/sparse.log`.

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
$ make rebuild-image@ppc64le@ubuntu
```

Note that the build mounts the source tree read-only, so nothing it does can
affect your source tree.
