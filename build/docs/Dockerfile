ARG from
FROM ${from}

ARG apt_mirror
ENV apt_mirror=${apt_mirror}
RUN [ -n "$apt_mirror" ] && sed -i -e "s|ports.ubuntu.com|$apt_mirror|" /etc/apt/sources.list || true

RUN apt-get -q -y update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -q -y install --no-install-recommends \
      build-essential \
      dvipng \
      fonts-dejavu \
      fonts-noto-cjk \
      gcc \
      gcc-powerpc64le-linux-gnu \
      g++-powerpc64le-linux-gnu \
      graphviz \
      imagemagick \
      latexmk \
      librsvg2-bin \
      make \
      perl-modules \
      python-is-python3 \
      python3-sphinx \
      python3-sphinx-rtd-theme \
      texlive-xetex \
      virtualenv \
      && \
    rm -rf /var/lib/apt/lists/* /var/cache/* /var/log/dpkg.log

RUN useradd linuxppc
USER linuxppc

COPY scripts/container-build.sh /bin/container-build.sh
COPY VERSION /VERSION
