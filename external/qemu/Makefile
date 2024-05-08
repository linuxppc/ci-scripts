VERSIONS := 4.2.1 \
	5.2.0 \
	6.2.0 \
	7.0.0 \
	7.1.0 \
	7.2.3 \
	8.2.3 \
	9.0.0

DEFAULT_VERSION = 8.2.3

help:
	@echo "qemu"
	@echo "Available targets:"
	@echo "  download        # download required sources"
	@echo "  prepare         # download and install dependencies"
	@echo "  build           # build default version (${DEFAULT_VERSION})"
	@echo "  build-all       # build all versions"
	@echo '  build-$$version  # build version $$version'


define TEMPLATE =
qemu-$(1).tar.xz:
	wget --no-verbose -O $$@.tmp https://download.qemu.org/qemu-$(1).tar.xz
	mv $$@.tmp $$@

prepare-$(1): qemu-$(1).tar.xz
	@./install-deps.sh

build-$(1): prepare-$(1)
	+@./build.sh $(1)

PHONY += prepare-$(1) build-$(1)
CLEAN_DIRS += qemu-$(1)
ALL_TARGETS += build-$(1)
endef

$(foreach version,${VERSIONS}, \
	$(eval $(call TEMPLATE,${version})) \
)

qemu-mainline.tar.xz:
	wget --no-verbose -O $@.tmp https://github.com/qemu/qemu/tarball/master
	mv $@.tmp $@

prepare-mainline: qemu-mainline.tar.xz
	@./install-deps.sh

build-mainline: prepare-mainline
	+@./build.sh mainline

PHONY += prepare-mainline build-mainline
CLEAN_DIRS += qemu-mainline
ALL_TARGETS += build-mainline

download: qemu-$(DEFAULT_VERSION).tar.xz

prepare: download
	@./install-deps.sh

build: download
	+@./build.sh $(DEFAULT_VERSION)

build-all: $(ALL_TARGETS)

clean:
	rm -rf $(CLEAN_DIRS)

distclean: clean
	rm -f *.tar.xz

.PHONY: download prepare build clean distclean help $(PHONY)
