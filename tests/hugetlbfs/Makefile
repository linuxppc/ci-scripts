help:
	@echo "hugetlbfs test"
	@echo "Available targets:"
	@echo "  download 	# download required sources"
	@echo "  prepare 	# download and install dependencies"
	@echo "  test 		# run the test"

version = 2.23
tarball = libhugetlbfs.tar.gz

download: $(tarball)

$(tarball):
	wget --no-verbose -O $@.tmp https://github.com/libhugetlbfs/libhugetlbfs/releases/download/$(version)/libhugetlbfs-$(version).tar.gz
	mv $@.tmp $@

prepare: download
	@./install-deps.sh

test: download
	+@./test.sh

clean:
	rm -rf libhugetlbfs log

distclean: clean
	rm -f $(tarball)

.PHONY: download prepare test clean distclean help
