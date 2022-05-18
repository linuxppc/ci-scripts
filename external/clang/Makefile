help:
	@echo "clang"
	@echo "Available targets:"
	@echo "  download       # download and unpack clang"
	@echo ""

VERSION := 14.0.0

clang.tar.xz:
	wget --no-verbose -O $@.tmp https://github.com/llvm/llvm-project/releases/download/llvmorg-$(VERSION)/clang+llvm-$(VERSION)-powerpc64le-linux-rhel-7.9.tar.xz
	mv $@.tmp $@

install/bin/clang: clang.tar.xz
	rm -rf install
	tar -xf clang.tar.xz
	mv clang+llvm-* install

download: install/bin/clang

prepare: download

build:

clean:
	@:

distclean: clean
	rm -rf install clang.tar.xz

.PHONY: download prepare build clean distclean help
