help:
	@echo "audit test"
	@echo "Available targets:"
	@echo "  download 	# download required sources"
	@echo "  prepare 	# download and install dependencies"
	@echo "  test 		# run the test"

tarball = audit-testsuite.tar.gz

download: $(tarball)

$(tarball):
	wget --no-verbose -O $@.tmp https://github.com/linux-audit/audit-testsuite/tarball/main
	mv $@.tmp $@

prepare: download
	@./install-deps.sh

test: download
	+@./test.sh

clean:
	rm -rf audit-testsuite log

distclean: clean
	rm -f $(tarball)

.PHONY: download prepare test clean distclean help
