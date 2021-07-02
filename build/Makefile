all: help

VERSION:
	@(git describe --always --long --dirty --abbrev=40) > VERSION

define MAIN_TEMPLATE =
image@${1}@${2} rebuild-image@${1}@${2}: VERSION

image@${1}@${2} rebuild-image@${1}@${2} pull-image@${1}@${2} push-image@${1}@${2}:
	@./scripts/image.sh $$@

clean@${1}@${2}:
	@./scripts/clean.sh $$@

CLEAN += clean@${1}@${2}
IMAGES += image@${1}@${2}
PULL_IMAGES += pull-image@${1}@${2}
REBUILD_IMAGES += rebuild-image@${1}@${2}
PUSH_IMAGES += push-image@${1}@${2}
endef

define KERNEL_TEMPLATE =
kernel@${1}@${2}: image@${1}@${2}
	@./scripts/build.sh $$@

clean-kernel@${1}@${2}:
	@./scripts/clean.sh $$@

KERNEL += kernel@${1}@${2}
endef

define SELFTESTS_TEMPLATE =
ppctests@${1}@${2} selftests@${1}@${2}: image@${1}@${2}
	@./scripts/build.sh $$@

clean-selftests@${1}@${2}:
	@./scripts/clean.sh $$@

PPCTESTS += ppctests@${1}@${2}
SELFTESTS += selftests@${1}@${2}
endef

define DOCS_TEMPLATE =
docs@${1}@${2}: image@${1}@${2}
	@./scripts/build.sh $$@

DOCS += docs@${1}@${2}
endef

BE_DISTROS := korg@4.9.4
ifeq ($(shell uname -m),x86_64)
BE_DISTROS += korg@4.6.3
endif

FEDORA_DISTROS := fedora@34 fedora@33 fedora@32 fedora@31
SELFTEST_DISTROS := ubuntu@21.04 ubuntu@20.10 ubuntu@20.04 ubuntu@18.04 ubuntu@16.04
KERNEL_DISTROS := korg@11.1.0 korg@10.3.0 korg@9.3.0 korg@8.1.0 korg@5.5.0 ${FEDORA_DISTROS}
DOCS_DISTRO := docs@20.04
X86_DISTRO := ubuntu@21.04
ALL_DISTROS := ${SELFTEST_DISTROS} ${BE_DISTROS} ${KERNEL_DISTROS}
SUBARCHES := ppc64le ppc64

$(eval $(call MAIN_TEMPLATE,ppc64le,${DOCS_DISTRO}))
$(eval $(call DOCS_TEMPLATE,ppc64le,${DOCS_DISTRO}))

$(eval $(call MAIN_TEMPLATE,x86_64,${X86_DISTRO}))
$(eval $(call KERNEL_TEMPLATE,x86_64,${X86_DISTRO}))

ifeq ($(shell uname -m),x86_64)
$(eval $(call SELFTESTS_TEMPLATE,x86_64,${X86_DISTRO}))
endif

$(foreach distro,${BE_DISTROS}, \
	$(eval $(call MAIN_TEMPLATE,ppc64,${distro})) \
	$(eval $(call KERNEL_TEMPLATE,ppc64,${distro})) \
)

$(foreach distro,${KERNEL_DISTROS}, \
	$(foreach subarch,${SUBARCHES}, \
		$(eval $(call MAIN_TEMPLATE,${subarch},${distro})) \
	) \
	$(foreach subarch,${SUBARCHES}, \
		$(eval $(call KERNEL_TEMPLATE,${subarch},${distro})) \
	) \
)

$(foreach distro,${SELFTEST_DISTROS}, \
	$(foreach subarch,${SUBARCHES}, \
		$(eval $(call MAIN_TEMPLATE,${subarch},${distro})) \
	) \
	$(foreach subarch,${SUBARCHES}, \
		$(eval $(call KERNEL_TEMPLATE,${subarch},${distro})) \
	) \
	$(foreach subarch,${SUBARCHES}, \
		$(eval $(call SELFTESTS_TEMPLATE,${subarch},${distro})) \
	) \
)

ifeq ($(shell uname -m),ppc64le)
$(foreach distro,${FEDORA_DISTROS}, \
	$(eval $(call SELFTESTS_TEMPLATE,ppc64le,${distro})) \
)
endif

clean: ${CLEAN}
	rm -f VERSION

kernel: ${KERNEL}
ppctests: ${PPCTESTS}
selftests: ${SELFTESTS}
images: ${IMAGES}
pull-images: ${PULL_IMAGES}
rebuild-images: ${REBUILD_IMAGES}
push-images: ${PUSH_IMAGES}
docs: ${DOCS}

ALL_TARGETS = ${KERNEL} ${PPCTESTS} ${SELFTESTS} ${IMAGES} ${PULL_IMAGES} ${DOCS} ${CLEAN}
.PHONY: ${ALL_TARGETS} VERSION

empty:=
space:= $(empty) $(empty)

help:
	@echo "Build docker images and build kernel and/or selftests inside them."
	@echo
	@echo "Targets are of the form:"
	@echo
	@echo "  kernel@<sub arch>@<distro & version>"
	@echo "  ppctests@<sub arch>@<distro & version>"
	@echo "  selftests@<sub arch>@<distro & version>"
	@echo "  clean@<sub arch>@<distro & version>"
	@echo
	@echo "Valid values for sub arch are:"
	@echo "   ${SUBARCHES}"
	@echo
	@echo "Valid values for distro & version are:"
	@echo "   ${ALL_DISTROS}"
	@echo
	@echo "So for example to build the kernel on ppc64le ubuntu 18.10 you'd use"
	@echo
	@echo "  make kernel@ppc64le@ubuntu@18.10"
	@echo
	@echo "However note that not all combinations are valid, as some distros"
	@echo "can't cross build the selftests."
	@echo
	@echo "You can also run all targets of a given type with, eg:"
	@echo
	@echo " $ make images         # build all images if they don't exist"
	@echo " $ make pull-images    # pull all images from docker hub"
	@echo " $ make rebuild-images # rebuild all images"
	@echo " $ make kernel         # build all kernel variants"
	@echo " $ make ppctests       # build all powerpc selftest variants"
	@echo " $ make selftests      # build all selftest variants"
	@echo " $ make clean          # clean everything"
	@echo
	@echo "To see all targets run:"
	@echo " $ make show_targets"
	@echo

TARGET_DISPLAY := $(subst ${space},\n,${ALL_TARGETS})

show_targets:
	@echo -e '${TARGET_DISPLAY}'
