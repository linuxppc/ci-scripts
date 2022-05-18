version=$(shell cat VERSION)

help:
	@echo "qemu-$(version)"
	@echo "Available targets:"
	@echo "  download       # download required sources"
	@echo "  prepare        # download and install dependencies"
	@echo "  build          # build it"

qemu.tar.xz:
	wget --no-verbose -O $@.tmp https://download.qemu.org/qemu-$(version).tar.xz
	mv $@.tmp $@

download: qemu.tar.xz

prepare: download
	@./install-deps.sh

build: download
	+@./build.sh

clean:
	rm -rf build src install log

distclean: clean
	rm -f qemu.tar.xz

.PHONY: download prepare build clean distclean help
