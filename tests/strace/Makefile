help:
	@echo "strace test"
	@echo "Available targets:"
	@echo "  download 	# download required sources"
	@echo "  prepare 	# download and install dependencies"
	@echo "  test 		# run the test"

version = 5.14
tarball = strace.tar.xz

download: $(tarball)

$(tarball):
	wget --no-verbose -O $@.tmp https://github.com/strace/strace/releases/download/v$(version)/strace-$(version).tar.xz
	mv $@.tmp $@

prepare: download
	@./install-deps.sh

test: download
	+@./test.sh

clean:
	rm -rf strace log

distclean: clean
	rm -f $(tarball)

.PHONY: download prepare test clean distclean help
