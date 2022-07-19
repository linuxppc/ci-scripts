ARG from
FROM ${from}

USER root

ARG apt_mirror
ENV apt_mirror=${apt_mirror}
RUN [ -n "$apt_mirror" ] && sed -i -e "s|ports.ubuntu.com|$apt_mirror|" /etc/apt/sources.list || true

RUN apt-get -q -y update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -q -y install --no-install-recommends \
      gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
      gcc-alpha-linux-gnu g++-alpha-linux-gnu \
      gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf \
      gcc-i686-linux-gnu g++-i686-linux-gnu \
      gcc-m68k-linux-gnu g++-m68k-linux-gnu \
      gcc-mips64el-linux-gnuabi64 g++-mips64el-linux-gnuabi64 \
      gcc-mipsel-linux-gnu g++-mipsel-linux-gnu \
      gcc-riscv64-linux-gnu g++-riscv64-linux-gnu \
      gcc-s390x-linux-gnu g++-s390x-linux-gnu \
      gcc-sh4-linux-gnu g++-sh4-linux-gnu \
      gcc-sparc64-linux-gnu g++-sparc64-linux-gnu \
      && \
    rm -rf /var/lib/apt/lists/* /var/cache/* /var/log/dpkg.log

USER linuxppc
