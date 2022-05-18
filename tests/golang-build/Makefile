help:
	@echo "Golang build test"
	@echo "Available targets:"
	@echo "  download 	# download required sources"
	@echo "  prepare 	# download and install dependencies"
	@echo "  test 		# run the test"

version = 1.16.6
tarball = go$(version).tar.gz

download: $(tarball)

$(tarball):
	wget --no-verbose -O $@.tmp https://github.com/golang/go/archive/refs/tags/$(tarball)
	mv $@.tmp $@

prepare: download
	@./install-deps.sh

test: download
	+@./test.sh

clean:
	rm -rf go-go$(version) log

distclean: clean
	rm -f $(tarball)

.PHONY: download prepare test clean distclean help
