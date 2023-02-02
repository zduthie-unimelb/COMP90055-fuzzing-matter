FROM ubuntu:22.04
SHELL ["/bin/bash", "-c"]

# Install dependencies
RUN apt-get -y update && \
    apt-get -y install sudo wget

# MATTER: Install dependencies    
RUN sudo apt-get -y install git gcc g++ pkg-config libssl-dev libdbus-1-dev \
     libglib2.0-dev libavahi-client-dev ninja-build python3-venv python3-dev \
     python3-pip unzip libgirepository1.0-dev libcairo2-dev libreadline-dev

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

# MATTER: Check out the Matter repository (tag V1.0.0.1)
RUN git clone https://github.com/project-chip/connectedhomeip.git ${MATTER_PATH}
RUN cd ${MATTER_PATH} && \
    git checkout tags/V1.0.0.1 && \
    git submodule update --init
# COPY --chown=ubuntu:ubuntu connectedhomeip $WORKDIR/connectedhomeip

# MATTER: Copy and apply custom patches for fuzzing
COPY --chown=ubuntu:ubuntu enable_libfuzzer.patch $WORKDIR/enable_libfuzzer.patch
COPY --chown=ubuntu:ubuntu disable_tsan.patch $WORKDIR/disable_tsan.patch
RUN cd ${WORKDIR} && git apply --directory=connectedhomeip enable_libfuzzer.patch
RUN cd ${WORKDIR} && git apply --directory=connectedhomeip disable_tsan.patch

# MATTER: Prepare for building
RUN source ${MATTER_PATH}/scripts/activate.sh

# MATTER: Compile with fuzzing enabled
RUN cd ${MATTER_PATH} && \
    ./scripts/run_in_build_env.sh "./scripts/build/build_examples.py --target linux-arm64-all-clusters-no-ble-asan-libfuzzer-clang build"