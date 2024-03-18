ARG from
FROM ${from}
ARG from

RUN apt-get -q -y update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -q -y install --no-install-recommends \
      bc \
      bison \
      bsdmainutils \
      bzip2 \
      ca-certificates \
      ccache \
      cpio \
      crossbuild-essential-powerpc \
      gcc-multilib-powerpc-linux-gnu \
      dwarves \
      file \
      flex \
      gcc \
      gcc-powerpc-linux-gnu g++-powerpc-linux-gnu \
      gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
      gcc-alpha-linux-gnu g++-alpha-linux-gnu \
      gcc-arc-linux-gnu g++-arc-linux-gnu \
      gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf \
      gcc-hppa-linux-gnu g++-hppa-linux-gnu \
      gcc-i686-linux-gnu g++-i686-linux-gnu \
      gcc-m68k-linux-gnu g++-m68k-linux-gnu \
      gcc-mips64el-linux-gnuabi64 g++-mips64el-linux-gnuabi64 \
      gcc-mipsel-linux-gnu g++-mipsel-linux-gnu \
      gcc-riscv64-linux-gnu g++-riscv64-linux-gnu \
      gcc-s390x-linux-gnu g++-s390x-linux-gnu \
      gcc-sh4-linux-gnu g++-sh4-linux-gnu \
      gcc-sparc64-linux-gnu g++-sparc64-linux-gnu \
      gcc-x86-64-linux-gnu g++-x86-64-linux-gnu \
      git \
      kmod \
      libc-dev \
      libelf-dev \
      libfuse-dev \
      liblz4-tool \
      libssl-dev \
      lzop \
      make \
      openssl \
      python3 \
      python3-dev \
      u-boot-tools \
      rename \
      rsync \
      sparse \
      xz-utils && \
    rm -rf /var/lib/apt/lists/* /tmp/packages.sh /var/cache/* /var/log/dpkg.log

ARG uid
ARG gid

RUN groupadd --gid $gid linuxppc
RUN useradd --uid $uid --gid $gid linuxppc
USER linuxppc

COPY scripts/container-build.sh /bin/container-build.sh
COPY VERSION /VERSION
