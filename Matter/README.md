# Setup

Build and run the Dockerfile (change default tag of `chip-build-uni` to whatever):
```
docker build . -t chip-build-uni
docker run --privileged --sysctl "net.ipv6.conf.all.disable_ipv6=0 net.ipv4.conf.all.forwarding=1 net.ipv6.conf.all.forwarding=1" -it chip-build-uni
```

Note that the Matter project requires special permissions, so make sure you run using the above command (with privileged and network arguments).

The Dockerfile is based on the official chip build image (`FROM connectedhomeip/chip-build:0.6.47`). The versions have been chosen to be compatible with the code based on the latest official release (1.0.0.2) at the beginning of our project. Some build steps have already changed if you want to incorporate newer versions of the Matter codebase repository (eg ZAP installation is no longer required in the latest versions of Matter).

# Standard workflows:

Once inside the Docker container, there are 6 fuzzers in total. 5 unit fuzzers, and 1 full-stack 'all-clusters-app' fuzzer.

| Name | Description |
| - | - |
| T1 - FuzzCertChip | Fuzz certificates in Matter TLV format |
| T2 - FuzzCertX509 | Fuzz certificates in X.509 DER format |
| T3 - FuzzTLVReader | Fuzz parsing of Matter TLV binary data |
| T4 - FuzzMDNSPacket | Fuzz parsing of mDNS packets |
| T5 - FuzzSetupPayload | Fuzz QR code commissioning payload |
| T6 - FuzzAllClusters | Fuzz UDP packets sent to simulated device |

## Unit fuzzers (T1-T5)

### 1. Build unit fuzzer binaries
Run the following (in the `connectedhomeip` directory) to build all unit fuzzers.

```
export BUILD_TYPE="clang"
./scripts/build/gn_gen.sh --args="is_clang=true use_coverage=true"
./scripts/run_in_build_env.sh "ninja -C out/$BUILD_TYPE"
```

### 2. Running the fuzzers and collecting coverage
Fuzzing analysis for unit fuzzers is performed in two steps:

1. Run the fuzzing binary (which generates a corpus). This can be done using the `integrations/libfuzzer/build_fuzz_run.sh` script.
2. Collect coverage by re-feeding that corpus into a coverage-enabled binary. This can be done using the `integrations/libfuzzer/build_fuzz_coverage.sh` script.

This produces zipped lcov reports that can be copied out of Docker and manually inspected.

#### T1 - FuzzCertChip
Run the fuzzer:
```
integrations/libfuzzer/build_fuzz_run.sh --driver=cert_chip --seeds=integrations/libfuzzer/cert_chip_seeds/ --dict=integrations/libfuzzer/tlv.dict --minutes=1440
```
(Generates a corpus `corpus_cert_chip_XXX_YYY`)

Capture coverage:
```
integrations/libfuzzer/build_fuzz_coverage.sh --driver=cert_chip --corpus=corpus_cert_chip_XXX_YYY/
```
(Generates `coverage_corpus_cert_chip_XXX_YYY.zip`)

#### T2 - FuzzCertX509
Run the fuzzer:
```
integrations/libfuzzer/build_fuzz_run.sh --driver=cert_der --seeds=integrations/libfuzzer/cert_der_seeds/ --dict=integrations/libfuzzer/asn1.dict --minutes=1440
```
(Generates a corpus `corpus_cert_der_XXX_YYY`)

Capture coverage:
```
integrations/libfuzzer/build_fuzz_coverage.sh --driver=cert_der --corpus=corpus_cert_der_XXX_YYY/
```
(Generates `coverage_corpus_cert_der_XXX_YYY.zip`)

#### T3 - FuzzTLVReader
Run the fuzzer:
```
integrations/libfuzzer/build_fuzz_run.sh --driver=tlv --seeds=integrations/libfuzzer/tlv_seeds/ --dict=integrations/libfuzzer/tlv.dict --minutes=1440
```
(Generates a corpus `corpus_tlv_XXX_YYY`)

Capture coverage:
```
integrations/libfuzzer/build_fuzz_coverage.sh --driver=tlv --corpus=corpus_tlv_XXX_YYY/
```
(Generates `coverage_corpus_tlv_XXX_YYY.zip`)

#### T4 - FuzzMDNSPacket
Run the fuzzer:
```
integrations/libfuzzer/build_fuzz_run.sh --driver=mdns --seeds=integrations/libfuzzer/mdns_seeds/ --dict=integrations/libfuzzer/mdns.dict --minutes=1440
```
(Generates a corpus `corpus_mdns_XXX_YYY`)

Capture coverage:
```
integrations/libfuzzer/build_fuzz_coverage.sh --driver=mdns --corpus=corpus_mdns_XXX_YYY/
```
(Generates `coverage_corpus_mdns_XXX_YYY.zip`)

#### T5 - FuzzSetupPayload
Run the fuzzer:
```
integrations/libfuzzer/build_fuzz_run.sh --driver="qr" --seeds=integrations/libfuzzer/qr_seeds/ --dict=integrations/libfuzzer/qr.dict --minutes=1440
```
(Generates a corpus `corpus_qr_XXX_YYY`)

Capture coverage:
```
integrations/libfuzzer/build_fuzz_coverage.sh --driver=qr --corpus=corpus_qr_XXX_YYY/
```
(Generates `coverage_corpus_qr_XXX_YYY.zip`)

### T6 - All Clusters App

T6 All-clusters-app fuzzing can be completed in one step using the script `integrations/libfuzzer/build_fuzz_clusters_coverage.sh`:

```
integrations/libfuzzer/build_fuzz_clusters_coverage.sh --seeds=integrations/libfuzzer/clusters_seeds/ --dict=integrations/libfuzzer/tlv.dict --minutes=1440
```
(Generates `/coverage_clusters_XXX_YYY.zip`)


# Additional Commands

Here are some other commands that have been useful when playing with Matter things:

Build a (non-fuzzing) all-clusters-app:

```
./scripts/run_in_build_env.sh "scripts/examples/gn_build_example.sh examples/all-clusters-app/linux out/all-clusters-app chip_config_network_layer_ble=false"
```

Build a (non-fuzzing) lock-app (used in generating seeds):

```
./scripts/run_in_build_env.sh "scripts/examples/gn_build_example.sh examples/lock-app/linux out/lock-app chip_config_network_layer_ble=false"
```

Build a (non-fuzzing) chip-tool (Matter controller to send commands):

```
./scripts/run_in_build_env.sh "scripts/examples/gn_build_example.sh examples/chip-tool out/chip-tool"
```

Specifically, to generate seeds, we built a lock-app in one Docker container, a chip-tool in another, and issued the following commands using the chip-tool whilst capturing the traffic:

```
sudo ./out/chip-tool/chip-tool discover commissionables
sudo ./out/chip-tool/chip-tool pairing onnetwork 111 20202021

sudo ./out/chip-tool/chip-tool doorlock lock-door 111 1 --timedInteractionTimeoutMs 2000
sudo ./out/chip-tool/chip-tool doorlock unlock-door 111 1 --timedInteractionTimeoutMs 2000

sudo ./out/chip-tool/chip-tool doorlock read lock-state 111 1
```