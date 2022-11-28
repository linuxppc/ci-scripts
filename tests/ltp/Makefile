help:
	@echo "ltp test"
	@echo "Available targets:"
	@echo "  download 	# download required sources"
	@echo "  prepare 	# download and install dependencies"
	@echo "  build 		# build the tests"
	@echo "  test 		# run the syscall test suite"

version = 20220930
tarball = ltp.tar.xz

download: $(tarball)

$(tarball):
	wget --no-verbose -O $@.tmp https://github.com/linux-test-project/ltp/releases/download/$(version)/ltp-full-$(version).tar.xz
	mv $@.tmp $@

prepare: download
	@./install-deps.sh

install: $(tarball)
	@./install-deps.sh
	+@./build.sh

build: install

test: install
	+@./test.sh -f syscalls

clean:
	rm -rf src log
	sudo rm -rf install

distclean: clean
	rm -f $(tarball)

.PHONY: download prepare build test clean distclean help
