# Setup

Build and run the Dockerfile:
```
docker build . -t chip-build-uni
docker run --privileged --sysctl "net.ipv6.conf.all.disable_ipv6=0 net.ipv4.conf.all.forwarding=1 net.ipv6.conf.all.forwarding=1" -it chip-build-uni
```


# Standard workflows:

### Build coverage ###
```
./scripts/build_coverage.sh
```

### All Clusters Fuzzing ###
```
mkdir objdir-clone
./scripts/run_in_build_env.sh "./scripts/build/build_examples.py --target linux-x64-all-clusters-no-ble-asan-libfuzzer-clang build"
```

### Unit / Integration Tests (clang) [including custom fuzz drivers] ###
```
export BUILD_TYPE="clang"
./scripts/build/gn_gen.sh --args="is_clang=true"
./scripts/run_in_build_env.sh "ninja -C out/$BUILD_TYPE"
```

