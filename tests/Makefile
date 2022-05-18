help:
	@echo "Tests"
	@echo "Available targets:"
	@echo "  download 	# download required sources"
	@echo "  prepare 	# download and install dependencies"
	@echo "  test 		# run the tests"
	@echo "  clean 		# clean up build files"
	@echo "  distclean 	# clean everything including downloads"

SUBDIRS := $(filter-out Makefile, $(wildcard *))

$(SUBDIRS):
	@$(MAKE) --no-print-directory -C $@ $(MAKECMDGOALS) 2>&1 | sed 's/^/$@: /'

download: $(SUBDIRS)

prepare: $(SUBDIRS)

test: $(SUBDIRS)

clean: $(SUBDIRS)

distclean: $(SUBDIRS)

.PHONY: download prepare test clean distclean help $(SUBDIRS)
