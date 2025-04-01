#!/usr/bin/env bash

# abort on error
set -eu

rm -rf ./target/debug/coverage/
rm -rf ./target/debug/profraw/
mkdir -p ./target/debug/coverage/
mkdir -p ./target/debug/profraw/

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="./target/debug/profraw/coverage-%p-%m.profraw"

cargo test

grcov ./target/debug/profraw/ \
    --binary-path ./target/debug/deps/ \
    --source-dir . \
    --output-type html \
    --branch \
    --ignore-not-existing \
    --ignore "/*" \
    --ignore "tests/*" \
    --output-path ./target/debug/coverage/

echo "Coverage report generated: $(pwd)/target/debug/coverage/index.html"

grcov ./target/debug/profraw/ \
    --binary-path ./target/debug/deps/ \
    --source-dir . \
    --output-type markdown \
    --branch \
    --ignore-not-existing \
    --ignore "/*" \
    --ignore "tests/*"
