ARG from
FROM ${from}

RUN dnf -y install --setopt=install_weak_deps=False \
        bc \
        bison \
        bzip2 \
        ccache \
        clang \
        cpio \
        diffutils \
        dwarves \
        elfutils-libelf-devel \
        findutils \
        flex \
        gawk \
        gcc \
        gcc-powerpc64le-linux-gnu \
        gcc-powerpc64-linux-gnu \
        git \
        glibc-devel \
        glibc-static \
        hostname \
        kmod \
        libmpc-devel \
        lld \
        llvm \
        lz4 \
        lzop \
        make \
        openssl \
        openssl-devel \
        perl \
        prename \
        rsync \
        sparse \
        uboot-tools \
        which \
        xz && \
    dnf clean all

COPY fedora/make-links.sh /tmp/make-links.sh
RUN /tmp/make-links.sh ${compiler_version} && rm /tmp/make-links.sh

RUN useradd linuxppc
USER linuxppc

COPY scripts/container-build.sh /bin/container-build.sh
COPY VERSION /VERSION
