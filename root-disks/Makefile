IMAGES += ppc64-rootfs.cpio.gz ppc64-novsx-rootfs.cpio.gz ppc64le-rootfs.cpio.gz
IMAGES += ppc-rootfs.cpio.gz
IMAGES += ubuntu16.04-cloudimg-powerpc.qcow2
IMAGES += ubuntu16.04-cloudimg-ppc64el.qcow2
IMAGES += ubuntu21.04-cloudimg-ppc64el.qcow2
IMAGES += ubuntu21.10-cloudimg-ppc64el.qcow2
IMAGES += ubuntu22.04-cloudimg-ppc64el.qcow2
IMAGES += fedora34-cloudimg-ppc64le.qcow2
IMAGES += fedora36-cloudimg-ppc64le.qcow2
IMAGES += fedora39-cloudimg-ppc64le.qcow2
IMAGES += debian-sid-powerpc.qcow2

build: prepare cloud-init-user-data.img

download: $(IMAGES)

prepare: download
	@./install-deps.sh

define wget
	wget -q -O $(1).tmp $(2)
	mv $(1).tmp $(1)
endef

define wget_lbt
	$(call wget,$(1),"https://github.com/groeck/linux-build-test/blob/236ccac32e5c3538f2c8221b359225cc40925ba0/rootfs/$(2)?raw=true")
endef

ppc64-rootfs.cpio.gz: ppc64-novsx-rootfs.cpio.gz
	ln -fs $< $@

ppc64-novsx-rootfs.cpio.gz:
	$(call wget_lbt,$@,ppc64/rootfs.cpio.gz)

ppc64le-rootfs.cpio.gz:
	$(call wget_lbt,$@,ppc64/rootfs-el.cpio.gz)

ppc-rootfs.cpio.gz:
	$(call wget_lbt,$@,ppc/rootfs.cpio.gz)

define wget_ubuntu
	$(call wget,$(1),"https://cloud-images.ubuntu.com/releases/$(2)/release/$(3)")
endef

ubuntu16.04-cloudimg-powerpc.qcow2:
	$(call wget_ubuntu,$@,xenial,ubuntu-16.04-server-cloudimg-powerpc-disk1.img)
	chmod a-w $@
	sha256sum $@ > $@.sum

ubuntu16.04-cloudimg-ppc64el.qcow2:
	$(call wget_ubuntu,$@,xenial,ubuntu-16.04-server-cloudimg-ppc64el-disk1.img)
	chmod a-w $@
	sha256sum $@ > $@.sum

ubuntu18.04-cloudimg-ppc64el.qcow2:
	$(call wget_ubuntu,$@,bionic,ubuntu-18.04-server-cloudimg-ppc64el.img)
	chmod a-w $@
	sha256sum $@ > $@.sum

ubuntu21.04-cloudimg-ppc64el.qcow2:
	$(call wget_ubuntu,$@,hirsute,ubuntu-21.04-server-cloudimg-ppc64el.img)
	chmod a-w $@
	sha256sum $@ > $@.sum

ubuntu21.10-cloudimg-ppc64el.qcow2:
	$(call wget_ubuntu,$@,impish,ubuntu-21.10-server-cloudimg-ppc64el.img)
	chmod a-w $@
	sha256sum $@ > $@.sum

ubuntu22.04-cloudimg-ppc64el.qcow2:
	$(call wget_ubuntu,$@,jammy,ubuntu-22.04-server-cloudimg-ppc64el.img)
	chmod a-w $@
	sha256sum $@ > $@.sum

define wget_fedora
	$(call wget,$(1),"https://download.fedoraproject.org/pub/fedora-secondary/releases/$(2)/Cloud/ppc64le/images/$(3)")
endef

define wget_fedora_old
	$(call wget,$(1),"https://archives.fedoraproject.org/pub/archive/fedora-secondary/releases/$(2)/Cloud/ppc64le/images/$(3)")
endef

fedora34-cloudimg-ppc64le.qcow2:
	$(call wget_fedora_old,$@,34,Fedora-Cloud-Base-34-1.2.ppc64le.qcow2)
	chmod a-w $@
	sha256sum $@ > $@.sum

fedora36-cloudimg-ppc64le.qcow2:
	$(call wget_fedora_old,$@,36,Fedora-Cloud-Base-36-1.5.ppc64le.qcow2)
	chmod a-w $@
	sha256sum $@ > $@.sum

fedora37-cloudimg-ppc64le.qcow2:
	$(call wget_fedora,$@,37,Fedora-Cloud-Base-37-1.7.ppc64le.qcow2)
	chmod a-w $@
	sha256sum $@ > $@.sum

fedora38-cloudimg-ppc64le.qcow2:
	$(call wget_fedora,$@,38,Fedora-Cloud-Base-38-1.6.ppc64le.qcow2)
	chmod a-w $@
	sha256sum $@ > $@.sum

fedora39-cloudimg-ppc64le.qcow2:
	$(call wget_fedora,$@,39,Fedora-Cloud-Base-39-1.5.ppc64le.qcow2)
	chmod a-w $@
	sha256sum $@ > $@.sum

debian-sid-powerpc.qcow2:
	$(call wget,$@.xz,"https://michael.ellerman.id.au/files/debian-sid-powerpc.qcow2.xz")
	unxz $@.xz
	chmod a-w $@
	sha256sum $@ > $@.sum

cloud-init-user-data.img: cloud-init-user-data.txt
	cloud-localds $@ $<

clean:
	rm -f cloud-init-user-data.img

distclean: clean
	rm -f $(IMAGES) *.sum

.PHONY: download prepare build clean distclean
