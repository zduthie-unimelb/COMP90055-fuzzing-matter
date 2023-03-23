# start with Ubuntu 20.04LTS
FROM ubuntu:focal
SHELL ["/bin/bash", "-c"]

# Install dependencies
RUN apt-get -y update && \
    apt-get -y install sudo wget vim tcpdump

# MATTER: Install dependencies    
RUN set -x \
    && sudo DEBIAN_FRONTEND=noninteractive apt-get install -fy --fix-missing \
    autoconf \
    automake \
    bison \
    bridge-utils \
    ccache \
    clang \
    clang-format \
    clang-tidy \
    curl \
    flex \
    g++ \
    git \
    git-lfs \
    gperf \
    iproute2 \
    jq \
    lcov \
    libavahi-client-dev \
    libavahi-common-dev \
    libcairo-dev \
    libcairo2-dev \
    libdbus-1-dev \
    libdbus-glib-1-dev \
    libdmalloc-dev \
    libgif-dev \
    libglib2.0-dev \
    libical-dev \
    libjpeg-dev \
    libmbedtls-dev \
    libncurses5-dev \
    libncursesw5-dev \
    libnl-3-dev \
    libnl-route-3-dev \
    libnspr4-dev \
    libpango1.0-dev \
    libpixman-1-dev \
    libreadline-dev \
    libsdl-pango-dev \
    libsdl2-dev \
    libssl-dev \
    libtool \
    libudev-dev \
    libusb-1.0-0 \
    libusb-dev \
    libxml2-dev \
    make \
    meson \
    net-tools \
    ninja-build \
    openjdk-8-jdk \
    pkg-config \
    python-is-python3 \
    python3.9 \
    python3.9-dev \
    python3.9-venv \
    rsync \
    shellcheck \
    strace \
    systemd \
    udev \
    unzip \
    wget \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/ \
    && git lfs install \
    && : # last line

# Matter: Cmake v3.23.1
RUN set -x \
    && (cd /tmp \
    && wget --progress=dot:giga https://github.com/Kitware/CMake/releases/download/v3.23.1/cmake-3.23.1-Linux-x86_64.sh \
    && sh cmake-3.23.1-Linux-x86_64.sh --exclude-subdir --prefix=/usr/local \
    && rm -rf cmake-3.23.1-Linux-x86_64.sh) \
    && exec bash \
    && : # last line

# Matter: Python 3.9 and PIP
RUN set -x \
    && DEBIAN_FRONTEND=noninteractive  apt-get update \
    && DEBIAN_FRONTEND=noninteractive  apt-get install -y libgirepository1.0-dev \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common \
    && add-apt-repository universe \
    && curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py \
    && python3.9 get-pip.py \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1 \
    && rm -rf /var/lib/apt/lists/ \
    && : # last line

RUN set -x \
    && pip3 install --no-cache-dir \
    attrs \
    click \
    coloredlogs \
    cxxfilt \
    flake8 \
    future \
    ghapi \
    mobly \
    pandas \
    portpicker \
    pygit \
    PyGithub \
    tabulate \
    && : # last line

# Matter: build and install gn
RUN set -x \
    && git clone https://gn.googlesource.com/gn \
    && cd gn \
    && python3 build/gen.py \
    && ninja -C out \
    && cp out/gn /usr/local/bin \
    && cd .. \
    && rm -rf gn \
    && : # last line

# Add a new user ubuntu, pass: ubuntu
RUN groupadd ubuntu && \
    useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -G sudo -u 1000 ubuntu -p "$(openssl passwd -1 ubuntu)"

# Use ubuntu as the default username
USER ubuntu
WORKDIR /home/ubuntu

ENV WORKDIR="/home/ubuntu"
ENV MATTER_PATH="${WORKDIR}/connectedhomeip"
ENV ZAP_INSTALL_PATH="${WORKDIR}/zap-linux"
# (TODO REMOVE)
ENV PATH="${PATH}:${ZAP_INSTALL_PATH}"

# MATTER: 'Install' ZAP
RUN wget "https://github.com/project-chip/zap/releases/download/v2023.01.19-nightly/zap-linux.zip" -O ${WORKDIR}/zap-linux.zip
RUN unzip ${WORKDIR}/zap-linux.zip -d ${ZAP_INSTALL_PATH}

# MATTER: Check out the Matter repository (tag v1.0.0.2)
RUN git clone https://github.com/project-chip/connectedhomeip.git ${MATTER_PATH}
RUN cd ${MATTER_PATH} && \
    git checkout tags/v1.0.0.2 && \
    git submodule update --init

# MATTER: Prepare for building
RUN source ${MATTER_PATH}/scripts/activate.sh

# MATTER: Copy and apply custom patches for fuzzing
COPY --chown=ubuntu:ubuntu enable_libfuzzer.patch $WORKDIR/enable_libfuzzer.patch
COPY --chown=ubuntu:ubuntu disable_tsan.patch $WORKDIR/disable_tsan.patch
# RUN cd ${WORKDIR} && git apply --directory=connectedhomeip enable_libfuzzer.patch
# RUN cd ${WORKDIR} && git apply --directory=connectedhomeip disable_tsan.patch

# MATTER: Compile all-clusters-app fuzzing build
# RUN cd ${MATTER_PATH} && \
#     ./scripts/run_in_build_env.sh "./scripts/build/build_examples.py --target linux-arm64-all-clusters-no-ble-asan-libfuzzer-clang build"

# MATTER: Run build_coverage script
# RUN cd ${MATTER_PATH} && \
#     ./scripts/run_in_build_env.sh "./scripts/build_coverage.sh"