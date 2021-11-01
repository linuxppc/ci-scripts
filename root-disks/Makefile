IMAGES += ppc64-rootfs.cpio.gz ppc64-novsx-rootfs.cpio.gz ppc64le-rootfs.cpio.gz
IMAGES += ppc-rootfs.cpio.gz
IMAGES += cloud-init-user-data.img
IMAGES += ubuntu16.04-cloudimg-powerpc.qcow2
IMAGES += ubuntu16.04-cloudimg-ppc64el.qcow2
IMAGES += ubuntu21.04-cloudimg-ppc64el.qcow2
IMAGES += ubuntu21.10-cloudimg-ppc64el.qcow2
IMAGES += fedora34-cloudimg-ppc64le.qcow2

all: $(IMAGES)

ppc64-rootfs.cpio.gz: ppc64-novsx-rootfs.cpio.gz
	ln -s $< $@

ppc64-novsx-rootfs.cpio.gz:
	wget -O $@.tmp "https://github.com/groeck/linux-build-test/blob/4e693ba1cfc17ff4c551626855d2982c492be1c2/rootfs/ppc64/rootfs.cpio.gz?raw=true"
	mv $@.tmp $@

ppc64le-rootfs.cpio.gz:
	wget -O $@.tmp "https://github.com/groeck/linux-build-test/blob/4e693ba1cfc17ff4c551626855d2982c492be1c2/rootfs/ppc64/rootfs-el.cpio.gz?raw=true"
	mv $@.tmp $@

ppc-rootfs.cpio.gz:
	wget -O $@.tmp "https://github.com/groeck/linux-build-test/blob/65335f1a683166c7b83d61a3eeaf400ebcfa20dd/rootfs/ppc/rootfs.cpio.gz?raw=true"
	mv $@.tmp $@

ubuntu16.04-cloudimg-powerpc.qcow2:
	wget -O $@.tmp "https://cloud-images.ubuntu.com/xenial/current/xenial-server-cloudimg-powerpc-disk1.img"
	mv $@.tmp $@
	chmod a-w $@
	sha256sum $@ > $@.sum

ubuntu16.04-cloudimg-ppc64el.qcow2:
	wget -O $@.tmp "https://cloud-images.ubuntu.com/xenial/current/xenial-server-cloudimg-ppc64el-disk1.img"
	mv $@.tmp $@
	chmod a-w $@
	sha256sum $@ > $@.sum

ubuntu21.04-cloudimg-ppc64el.qcow2:
	wget -O $@.tmp "https://cloud-images.ubuntu.com/hirsute/current/hirsute-server-cloudimg-ppc64el.img"
	mv $@.tmp $@
	chmod a-w $@
	sha256sum $@ > $@.sum

ubuntu21.10-cloudimg-ppc64el.qcow2:
	wget -O $@.tmp "https://cloud-images.ubuntu.com/impish/current/impish-server-cloudimg-ppc64el.img"
	mv $@.tmp $@
	chmod a-w $@
	sha256sum $@ > $@.sum

fedora34-cloudimg-ppc64le.qcow2:
	wget -O $@.tmp "https://download.fedoraproject.org/pub/fedora-secondary/releases/34/Cloud/ppc64le/images/Fedora-Cloud-Base-34-1.2.ppc64le.qcow2"
	mv $@.tmp $@
	chmod a-w $@
	sha256sum $@ > $@.sum

cloud-init-user-data.img: cloud-init-user-data.txt
	cloud-localds $@ $<

clean:
	@echo "Use distclean to remove rootfs images"

distclean:
	rm -f $(IMAGES)
