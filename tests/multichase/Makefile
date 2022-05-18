help:
	@echo "multichase test"
	@echo "Available targets:"
	@echo "  download 	# download required sources"
	@echo "  prepare 	# download and install dependencies"
	@echo "  test 		# run the test"

tarball = multichase.tar.gz

download: $(tarball)

$(tarball):
	wget --no-verbose -O $@.tmp https://github.com/google/multichase/tarball/master
	mv $@.tmp $@

prepare: download
	@./install-deps.sh

test: download
	+@./test.sh

clean:
	rm -rf multichase log

distclean: clean
	rm -f $(tarball)

.PHONY: download prepare test clean distclean help
