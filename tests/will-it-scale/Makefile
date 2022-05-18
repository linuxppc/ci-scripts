help:
	@echo "will-it-scale test"
	@echo "Available targets:"
	@echo "  download 	# download required sources"
	@echo "  prepare 	# download and install dependencies"
	@echo "  test 		# run the test"

tarball = will-it-scale.tar.gz

download: $(tarball)

$(tarball):
	wget --no-verbose -O $@.tmp https://github.com/antonblanchard/will-it-scale/tarball/master
	mv $@.tmp $@

prepare: download
	@./install-deps.sh

test: download
	+@./test.sh

clean:
	rm -rf will-it-scale log

distclean: clean
	rm -f $(tarball)

.PHONY: download prepare test clean distclean help
