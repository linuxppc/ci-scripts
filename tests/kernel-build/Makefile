help:
	@echo "kernel build test"
	@echo "Available targets:"
	@echo "  download 	# download required sources"
	@echo "  prepare 	# download and install dependencies"
	@echo "  test 		# run the test"

tarball = linux.tar.xz

download: $(tarball)

$(tarball):
	wget --no-verbose -O $@.tmp http://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.15.tar.xz
	mv $@.tmp $@

prepare: download
	@./install-deps.sh

test: download
	+@./test.sh

clean:
	rm -rf linux log

distclean: clean
	rm -f $(tarball)

.PHONY: download prepare test clean distclean help
