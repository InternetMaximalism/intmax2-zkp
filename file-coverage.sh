#!/usr/bin/env bash

set -eu

if [ $# -lt 1 ]; then
  echo "Usage: $0 <file_path> [test_pattern]"
  echo "Example: $0 src/lib.rs"
  echo "Example: $0 src/models/user.rs user_test"
  exit 1
fi

FILE_PATH=$1
TEST_PATTERN=${2:-""}

# src/models/user.rs -> models::user
MODULE_PATH=$(echo ${FILE_PATH} | sed 's/^src\///g' | sed 's/\.rs$//g' | sed 's/\//::/'g)

COVERAGE_DIR="./target/debug/coverage_${MODULE_PATH//::/_}"
PROFRAW_DIR="./target/debug/profraw_${MODULE_PATH//::/_}"

rm -rf "${COVERAGE_DIR}"
rm -rf "${PROFRAW_DIR}"
mkdir -p "${COVERAGE_DIR}"
mkdir -p "${PROFRAW_DIR}"

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="${PROFRAW_DIR}/coverage-%p-%m.profraw"

if [ -z "${TEST_PATTERN}" ]; then
  echo "Running tests for module: ${MODULE_PATH}"
  cargo test ${MODULE_PATH}
else
  echo "Running tests for module: ${MODULE_PATH} with pattern: ${TEST_PATTERN}"
  cargo test ${MODULE_PATH}::${TEST_PATTERN}
fi

echo "Generating coverage report for file: ${FILE_PATH}"
grcov "${PROFRAW_DIR}" \
  --binary-path ./target/debug/deps/ \
  --source-dir . \
  --output-type html \
  --branch \
  --ignore-not-existing \
  --ignore "/*" \
  --keep-only "${FILE_PATH}" \
  --output-path "${COVERAGE_DIR}"


echo "Generating coverage summary for file: ${FILE_PATH}"
grcov "${PROFRAW_DIR}" \
  --binary-path ./target/debug/deps/ \
  --source-dir . \
  --output-type markdown \
  --branch \
  --ignore-not-existing \
  --ignore "/*" \
  --keep-only "${FILE_PATH}"

echo "Coverage report generated: $(pwd)/${COVERAGE_DIR}/index.html"