#!/bin/bash

RUSTFLAGS="-D warnings" CARGO_TARGET_DIR="target/bpf" "cargo" "+nightly-2022-10-10" "rustc" "--package=ebpf-testing" "--bin=kern-code" "--features=kern" "--no-default-features" "--target=bpfel-unknown-none" "-Z" "build-std=core" "--release" "--" "-Cdebuginfo=2" "-Clink-arg=--disable-memory-builtins" "-Clink-arg=--keep-btf"

compCode=$?
if [ $compCode -ne 0 ]; then
    exit $compCode
fi

cargo build -r

compCode=$?
if [ $compCode -ne 0 ]; then
    exit $compCode
fi

sudo -E RUST_LOG=info ./target/release/ebpf-recoder