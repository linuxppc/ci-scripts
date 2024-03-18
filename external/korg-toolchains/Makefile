help:
	@echo "korg-toolchains"
	@echo "Available targets:"
	@echo "  download              # download and unpack toolchains"
	@echo '  download-all-$$arch    # download all toolchains for arch'
	@echo '  download-all-$$version # download all toolchains for version'
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

ALL_version_$(1) += gcc-$(1)-nolibc/$(2)-linux
ALL_arch_$(2) += gcc-$(1)-nolibc/$(2)-linux
ALL_TARGETS += gcc-$(1)-nolibc/$(2)-linux
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

VERSIONS := 13.2.0 \
	13.1.0 \
	12.3.0 \
	12.2.0 \
	12.1.0 \
	11.4.0 \
	11.3.0 \
	11.1.0 \
	10.5.0 \
	10.4.0 \
	10.3.0 \
	10.1.0 \
	9.5.0 \
	9.4.0 \
	9.3.0 \
	9.2.0 \
	8.5.0 \
	8.4.0 \
	8.3.0 \
	8.1.0 \
	7.5.0 \
	7.3.0 \
	6.5.0 \
	6.4.0 \
	5.5.0

$(foreach arch,${ARCHES}, \
	$(foreach version,${VERSIONS}, \
		$(eval $(call TEMPLATE,${version},${arch})) \
	) \
)

$(foreach arch,${ARCHES}, \
	$(eval download-all-$(arch): $(ALL_arch_$(arch))) \
)

$(foreach version,${VERSIONS}, \
	$(eval download-all-$(version): $(ALL_version_$(version))) \
)

download-all: $(ALL_TARGETS)

CLEAN_DIRS := $(patsubst %,gcc-%-nolibc,$(VERSIONS))

# Only download powerpc 13.2.0 & 5.5.0 by default
download: gcc-13.2.0-nolibc/powerpc64-linux gcc-5.5.0-nolibc/powerpc64-linux

prepare: download

build:

clean:
	@:

distclean: clean
	rm -rf $(CLEAN_DIRS) *.tar.xz

.PHONY: download prepare build clean distclean help
