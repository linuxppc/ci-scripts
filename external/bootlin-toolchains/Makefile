host_arch=$(shell uname -m)
ifeq ($(host_arch),x86_64)

# $1 = arch, $2 = version
define TEMPLATE =
$(1)--$(2):
	rm -f $(1)--$(2).tar.bz2
	wget --no-verbose https://toolchains.bootlin.com/downloads/releases/toolchains/$(1)/tarballs/$(1)--$(2).tar.bz2
	tar -xf $(1)--$(2).tar.bz2
	touch $$@
	rm -f $(1)--$(2).tar.bz2

ALL_version_$(2) += $(1)--$(2)
ALL_arch_$(1) += $(1)--$(2)
ALL_TARGETS += $(1)--$(2)
endef

ARCHES := powerpc-440fp \
	powerpc-e300c3 \
	powerpc-e500mc \
	powerpc64-e5500 \
	powerpc64-e6500 \
	powerpc64-power8 \
	powerpc64le-power8 

VERSIONS := glibc--stable-2024.02-1

DEFAULT := powerpc64-power8--glibc--stable-2024.02-1 powerpc64le-power8--glibc--stable-2024.02-1

help:
	@echo "bootlin-toolchains"
	@echo "Available targets:"
	@echo "  download              # download and unpack toolchains"
	@echo '  download-all-$$arch    # download all toolchains for arch'
	@echo '  download-all-$$version # download all toolchains for version'
	@echo ""
else
help:
	@echo "bootlin-toolchains"
	@echo "No toolchains available for this architecture"
endif


$(foreach arch,${ARCHES}, \
	$(foreach version,${VERSIONS}, \
		$(eval $(call TEMPLATE,${arch},${version})) \
	) \
)

$(foreach arch,${ARCHES}, \
	$(eval download-all-$(arch): $(ALL_arch_$(arch))) \
)

$(foreach version,${VERSIONS}, \
	$(eval download-all-$(version): $(ALL_version_$(version))) \
)

download-all: $(ALL_TARGETS)

CLEAN_DIRS := $(patsubst %,%--*,$(ARCHES))

download: $(DEFAULT)

prepare: download

build:

clean:
	@:

distclean: clean
	rm -rf $(CLEAN_DIRS) *.tar.xz

.PHONY: download prepare build clean distclean help
