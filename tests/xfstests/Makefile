help:
	@echo "xfstests"
	@echo "Available targets:"
	@echo "  download 	# download required sources"
	@echo "  prepare 	# download and install dependencies"
	@echo "  test 		# builds the tests"

tarball = xfstests.tar.gz

download: $(tarball)

$(tarball):
	wget --no-verbose -O $@.tmp https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/snapshot/master.tar.gz
	mv $@.tmp $@

prepare: download
	@./install-deps.sh

test: download
	+@./test.sh

clean:
	rm -rf xfstests log

distclean: clean
	rm -f $(tarball)

.PHONY: download prepare test clean distclean help
