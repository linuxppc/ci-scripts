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
        xz && \
    dnf clean all

COPY fedora/make-links.sh /tmp/make-links.sh
RUN /tmp/make-links.sh ${compiler_version} && rm /tmp/make-links.sh

ARG uid
ARG gid

RUN groupadd --gid $gid linuxppc
RUN useradd --uid $uid --gid $gid linuxppc
USER linuxppc

COPY scripts/container-build.sh /bin/container-build.sh
COPY VERSION /VERSION
