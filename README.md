# COMP90055-fuzzing-matter
Repository for COMP90055 Research Project 'Automated Network Protocol Testing'. Fuzzing the Matter (formerly Project CHIP) Protocol.

## Instructions

1. Build and run the Dockerfile:
```
docker build . -t fuzzing-matter --pull
docker run -it fuzzing-matter
```

Grab a coffee (or 10). Build took ~90 minutes on M1 Macbook Pro.

2. The last line of the Dockerfile builds the fuzzing variant of the all-clusters-app. You can then run it from inside the Docker container by executing: `connectedhomeip/out/linux-arm64-all-clusters-no-ble-asan-libfuzzer-clang/chip-all-clusters-app-fuzzing` (file should exist)

Notes:
- `--pull` forces Docker to pull a fresh copy of the Ubuntu image (useful to avoid platform architecture caches)
- (Optional) The default Docker Ubuntu platform for Mac M1 is [linux/arm64/v8](https://hub.docker.com/layers/library/ubuntu/22.04/images/sha256-13e180ab78513dbe30a4f5a9e35acc6f61d92cbccac887a4f11ea23516261cc0?context=explore). Can manually specify alternatives via adding docker build argument `--platform=linux/amd64`
