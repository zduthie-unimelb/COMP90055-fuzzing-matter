# start with Ubuntu 20.04LTS
FROM ubuntu:20.04

RUN chmod 777 /usr/lib &&\
    chmod 777 /opt

# Install dependencies
RUN apt-get -y update && \
    apt-get -y install git sudo wget vim tcpdump openssl clang

# Add a new user ubuntu, pass: ubuntu
RUN groupadd ubuntu && \
    useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -G sudo -u 1000 ubuntu -p "$(openssl passwd -1 ubuntu)"

# Use ubuntu as default username
USER ubuntu
WORKDIR /home/ubuntu

RUN git clone https://github.com/google/fuzzing.git fuzzing

# Get fuzzer-test-suite
RUN git clone https://github.com/google/fuzzer-test-suite.git FTS

# # Get deps
# RUN ./fuzzing/tutorial/libFuzzer/install-deps.sh
# # Get fresh clang binaries
# RUN ./fuzzing/tutorial/libFuzzer/install-clang.sh
