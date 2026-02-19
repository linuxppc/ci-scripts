ARG from
FROM ${from}
ARG from

COPY ubuntu/packages.sh /tmp/packages.sh

ARG apt_mirror
ENV apt_mirror=${apt_mirror}
RUN [ -n "$apt_mirror" ] && sed -i -e "s|ports.ubuntu.com|$apt_mirror|" /etc/apt/sources.list || true

# Deal with Ubuntu 21/22.10 repos moving to old-releases (ppc64le only)
RUN if echo "$from" | grep -q ".*ubuntu:2[12]\.10"; then sed -i -e "s|ports.ubuntu.com/ubuntu-ports|old-releases.ubuntu.com/ubuntu|" /etc/apt/sources.list; fi

RUN apt-get -q -y update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -q -y install --no-install-recommends \
      bc \
      bindgen \
      bison \
      bsdmainutils \
      bzip2 \
      ca-certificates \
      ccache \
      cpio \
      crossbuild-essential-powerpc \
      curl \
      gcc-multilib-powerpc-linux-gnu \
      dwarves \
      file \
      flex \
      gawk \
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
      lld \
      llvm \
      lzop \
      make \
      openssl \
      python3 \
      python3-dev \
      u-boot-tools \
      rename \
      rsync \
      rustc \
      rustfmt \
      rust-clippy \
      rust-src \
      sparse \
      xz-utils \
      $(/tmp/packages.sh) && \
    rm -rf /var/lib/apt/lists/* /tmp/packages.sh /var/cache/* /var/log/dpkg.log
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV PATH="/opt/cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --no-modify-path
RUN rustup toolchain install nightly-2026-01-28 \
    && rustup default nightly-2026-01-28 \
    && rustup component add rust-src --toolchain nightly-2026-01-28 \
    && cargo install --locked bindgen-cli
COPY ubuntu/make-links.sh /tmp/make-links.sh
RUN /tmp/make-links.sh ${compiler_version} && rm /tmp/make-links.sh

RUN useradd linuxppc
USER linuxppc

COPY scripts/container-build.sh /bin/container-build.sh
COPY VERSION /VERSION
