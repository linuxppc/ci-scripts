ARG from
FROM ${from}

COPY ubuntu/packages.sh /tmp/packages.sh

ARG apt_mirror
ENV apt_mirror=${apt_mirror}
RUN [ -n "$apt_mirror" ] && sed -i -e "s|ports.ubuntu.com|$apt_mirror|" /etc/apt/sources.list || true

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
      gcc-powerpc-linux-gnu \
      g++-powerpc-linux-gnu \
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
      u-boot-tools \
      rename \
      rsync \
      xz-utils \
      $(/tmp/packages.sh) && \
    rm -rf /var/lib/apt/lists/* /tmp/packages.sh /var/cache/* /var/log/dpkg.log

COPY ubuntu/make-links.sh /tmp/make-links.sh
RUN /tmp/make-links.sh ${compiler_version} && rm /tmp/make-links.sh

ARG uid
ARG gid

RUN groupadd --gid $gid linuxppc
RUN useradd --uid $uid --gid $gid linuxppc
USER linuxppc

COPY scripts/container-build.sh /bin/container-build.sh
COPY VERSION /VERSION
