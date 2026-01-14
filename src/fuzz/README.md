# NextGCore Fuzzing Infrastructure

This directory contains fuzzing targets for NextGCore protocol parsers.

## Prerequisites

Install `cargo-fuzz`:

```bash
cargo install cargo-fuzz
```

You'll also need the nightly Rust toolchain:

```bash
rustup install nightly
```

## Available Fuzz Targets

| Target | Protocol | Description |
|--------|----------|-------------|
| `fuzz_pfcp_message` | PFCP | N4 interface (SMF ↔ UPF) |
| `fuzz_gtp_message` | GTPv1-C/GTPv2-C | Gn/Gp/S5/S8/S11 interfaces |
| `fuzz_nas_message` | 5G NAS / EPS NAS | 5GMM/5GSM/EMM/ESM messages |
| `fuzz_diameter_message` | Diameter | S6a/S6b/Gx/Gy/Rx/Cx/SWx interfaces |

## Running Fuzzers

### Run a specific fuzzer

```bash
cd /path/to/nextgcore/rust_src/fuzz
cargo +nightly fuzz run fuzz_pfcp_message
```

### Run with specific options

```bash
# Run for 60 seconds
cargo +nightly fuzz run fuzz_pfcp_message -- -max_total_time=60

# Run with 4 parallel jobs
cargo +nightly fuzz run fuzz_pfcp_message -- -jobs=4 -workers=4

# Run with specific dictionary
cargo +nightly fuzz run fuzz_pfcp_message -- -dict=dictionaries/pfcp.dict
```

### Check coverage

```bash
cargo +nightly fuzz coverage fuzz_pfcp_message
```

### List crashes

```bash
cargo +nightly fuzz list
```

### Minimize a crash

```bash
cargo +nightly fuzz tmin fuzz_pfcp_message artifacts/fuzz_pfcp_message/crash-xxxxx
```

## Adding Seed Corpus

Create seed files with valid protocol messages to improve fuzzing efficiency:

```bash
mkdir -p corpus/fuzz_pfcp_message/
# Add valid PFCP message samples as binary files
```

## Security Notes

- These fuzzers test parser robustness against malformed input
- Any crashes should be investigated as potential security vulnerabilities
- Report security issues responsibly

## Protocol References

- PFCP: 3GPP TS 29.244
- GTPv1-C: 3GPP TS 29.060
- GTPv2-C: 3GPP TS 29.274
- 5G NAS: 3GPP TS 24.501
- EPS NAS: 3GPP TS 24.301
- Diameter: RFC 6733, 3GPP TS 29.272/273/212/214/229
