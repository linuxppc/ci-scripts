help:
	@echo "External packages"
	@echo "Available targets:"
	@echo "  download 	# download required sources"
	@echo "  prepare 	# download and install dependencies"
	@echo "  build		# build"
	@echo "  clean 		# clean up build files"
	@echo "  distclean 	# clean everything including downloads"

SUBDIRS := $(filter-out Makefile, $(wildcard *))

$(SUBDIRS):
	@$(MAKE) --no-print-directory -C $@ $(MAKECMDGOALS) 2>&1 | sed 's/^/$@: /'

download: $(SUBDIRS)

prepare: $(SUBDIRS)

build: $(SUBDIRS)

clean: $(SUBDIRS)

distclean: $(SUBDIRS)

.PHONY: download prepare build clean distclean help $(SUBDIRS)
