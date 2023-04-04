# start with official chip-build (update version accordingly)
FROM connectedhomeip/chip-build:0.6.47
SHELL ["/bin/bash", "-c"]

# Install dependencies
RUN apt-get -y update && \
    apt-get -y install sudo wget vim tcpdump

# Add a new user ubuntu, pass: ubuntu
RUN groupadd ubuntu && \
    useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -G sudo -u 1000 ubuntu -p "$(openssl passwd -1 ubuntu)"

# Use ubuntu as the default username
USER ubuntu
WORKDIR /home/ubuntu

ENV WORKDIR="/home/ubuntu"
ENV MATTER_PATH="${WORKDIR}/connectedhomeip"

### MATTER ###
# Checkout
RUN git clone --depth=1 https://github.com/project-chip/connectedhomeip.git ${MATTER_PATH}
# Checkout submodules
RUN cd ${MATTER_PATH} && scripts/checkout_submodules.py --shallow --platform linux
# Bootstrap
RUN cd ${MATTER_PATH} && mkdir -p /tmp/log_output ; scripts/build/gn_bootstrap.sh ;
# Activate environment
RUN source ${MATTER_PATH}/scripts/activate.sh

# MATTER: Copy and apply custom patches for fuzzing
COPY --chown=ubuntu:ubuntu enable_libfuzzer.patch $WORKDIR/enable_libfuzzer.patch
COPY --chown=ubuntu:ubuntu disable_tsan.patch $WORKDIR/disable_tsan.patch
# RUN cd ${WORKDIR} && git apply --directory=connectedhomeip enable_libfuzzer.patch
# RUN cd ${WORKDIR} && git apply --directory=connectedhomeip disable_tsan.patch