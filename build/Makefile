all: help

export FEDORA_LATEST := 35
export UBUNTU_LATEST := 22.04

# If we're on ppc64le
ifeq ($(shell uname -m),ppc64le)
    # And we don't see ISA v3.0
    ifeq ($(shell LD_SHOW_AUXV=1 /bin/true | grep "AT_HWCAP2:.*\barch_3_00\b"),)
        # Then we can't use 22.04
        UBUNTU_LATEST := 21.10
    endif
endif

FEDORA_DISTROS := fedora@${FEDORA_LATEST} fedora@34 fedora@33 fedora@31 fedora
# Sort is to elimiate duplicates if UBUNTU_LATEST == 21.10
UBUNTU_DISTROS := $(sort ubuntu@${UBUNTU_LATEST} ubuntu@21.10 ubuntu@21.04 ubuntu@20.04 ubuntu@18.04 ubuntu@16.04 ubuntu)
KORG_DISTROS := korg@11.1.0 korg@10.3.0 korg@9.3.0 korg@8.1.0 korg@5.5.0
ALL_DISTROS := ${UBUNTU_DISTROS} ${KORG_DISTROS} ${FEDORA_DISTROS}
DOCS_DISTRO := docs@${UBUNTU_LATEST}
X86_DISTRO := ubuntu@${UBUNTU_LATEST}
ALIAS_DISTROS := ubuntu fedora
SUBARCHES := ppc64le ppc64 ppc

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

KERNEL += $(if $(filter-out ${ALIAS_DISTROS},${2}), kernel@${1}@${2})
endef

define SELFTESTS_TEMPLATE =
ppctests@${1}@${2} selftests@${1}@${2}: image@${1}@${2}
	@./scripts/build.sh $$@

clean-selftests@${1}@${2}:
	@./scripts/clean.sh $$@

PPCTESTS += $(if $(filter-out ${ALIAS_DISTROS},${2}), ppctests@${1}@${2})
SELFTESTS += $(if $(filter-out ${ALIAS_DISTROS},${2}), selftests@${1}@${2})
endef

define PERF_TEMPLATE =
perf@${1}@${2}: image@${1}@${2}
	@./scripts/build.sh $$@

clean-perf@${1}@${2}:
	@./scripts/clean.sh $$@

PERF += $(if $(filter-out ${ALIAS_DISTROS},${2}), perf@${1}@${2})
endef

define DOCS_TEMPLATE =
docs@${1}@${2}: image@${1}@${2}
	@./scripts/build.sh $$@

DOCS += docs@${1}@${2}
endef

$(eval $(call MAIN_TEMPLATE,ppc64le,${DOCS_DISTRO}))
$(eval $(call DOCS_TEMPLATE,ppc64le,${DOCS_DISTRO}))

$(eval $(call MAIN_TEMPLATE,x86_64,${X86_DISTRO}))
$(eval $(call KERNEL_TEMPLATE,x86_64,${X86_DISTRO}))

ifeq ($(shell uname -m),x86_64)
$(eval $(call SELFTESTS_TEMPLATE,x86_64,${X86_DISTRO}))
endif

$(foreach distro,${ALL_DISTROS}, \
	$(foreach subarch,${SUBARCHES}, \
		$(eval $(call MAIN_TEMPLATE,${subarch},${distro})) \
	) \
	$(foreach subarch,${SUBARCHES}, \
		$(eval $(call KERNEL_TEMPLATE,${subarch},${distro})) \
	) \
)

$(foreach distro,${UBUNTU_DISTROS}, \
	$(foreach subarch,${SUBARCHES}, \
		$(eval $(call SELFTESTS_TEMPLATE,${subarch},${distro})) \
	) \
	$(foreach subarch,${SUBARCHES}, \
		$(eval $(call PERF_TEMPLATE,${subarch},${distro})) \
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
perf: ${PERF}
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
