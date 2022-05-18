help:
	@echo "See README.md for help"

SUBDIRS := root-disks external tests

$(SUBDIRS):
	@$(MAKE) --no-print-directory -C $@ $(MAKECMDGOALS) 2>&1 | sed 's/^/$@: /'

download: $(SUBDIRS)

prepare: $(SUBDIRS)

build: external

clean: $(SUBDIRS)

distclean: $(SUBDIRS)

.PHONY: download prepare build clean distclean help $(SUBDIRS)
