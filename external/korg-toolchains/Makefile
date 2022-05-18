help:
	@echo "korg-toolchains"
	@echo "Available targets:"
	@echo "  download       # download and unpack toolchains"
	@echo ""
	@echo "Download additional toolchains with:"
	@echo "  $ make gcc-<version>-nolibc/<arch>-linux"

host_arch=$(shell uname -m)

define TEMPLATE =
gcc-$(1)-nolibc/$(2)-linux:
	rm -f gcc-$(1)-nolibc-$(2)-linux.tar.xz
	wget --no-verbose -O gcc-$(1)-nolibc-$(2)-linux.tar.xz https://mirrors.edge.kernel.org/pub/tools/crosstool/files/bin/$(host_arch)/$(1)/$(host_arch)-gcc-$(1)-nolibc-$(2)-linux.tar.xz
	tar -xf gcc-$(1)-nolibc-$(2)-linux.tar.xz
	touch $$@
	rm gcc-$(1)-nolibc-$(2)-linux.tar.xz
endef

ARCHES := alpha \
	aarch64 \
	arc \
	csky \
	hppa \
	hppa64 \
	i386 \
	ia64 \
	m68k \
	microblaze \
	mips \
	mips64 \
	nds32le \
	nios2 \
	or1k \
	powerpc \
	powerpc64 \
	riscv32 \
	riscv64 \
	s390 \
	sh2 \
	sh4 \
	sparc \
	sparc64 \
	x86_64 \
	xtensa

VERSIONS := 11.1.0 5.5.0

$(foreach arch,${ARCHES}, \
	$(foreach version,${VERSIONS}, \
		$(eval $(call TEMPLATE,${version},${arch})) \
	) \
)


CLEAN_DIRS := $(patsubst %,gcc-%-nolibc,$(VERSIONS))

# Only download powerpc 11.1.0 & 5.5.0 by default
download: gcc-11.1.0-nolibc/powerpc64-linux gcc-5.5.0-nolibc/powerpc64-linux

prepare: download

build:

clean:
	@:

distclean: clean
	rm -rf $(CLEAN_DIRS)

.PHONY: download prepare build clean distclean help
