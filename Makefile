# SPDX-License-Identifier: GPL-3.0-or-later
#
#   make              build the CUDA searcher (cuda/website-vanity-gpu)
#   make test         host-side BLAKE3 known-answer test (no GPU needed)
#   make rust         build the CPU website search and mail-vanity (cargo)
#   make rust-test    run the Rust unit tests
#   make venv         create .venv with the Python dependency for fn-vanity/fn-words
#
# ARCH picks the GPU architecture: sm_120 is the RTX 50 series (CUDA >= 12.8),
# sm_89 the RTX 40 series, sm_86 the RTX 30 series.

NVCC  ?= nvcc
CXX   ?= g++
ARCH  ?= sm_120
PYTHON ?= python3

GPU_BIN  := cuda/website-vanity-gpu
TEST_BIN := cuda/test_blake3
HEADERS  := cuda/ed25519_fast.cuh cuda/blake3_64.cuh

.PHONY: all test rust rust-test venv clean

all: $(GPU_BIN)

$(GPU_BIN): cuda/website-vanity.cu $(HEADERS)
	$(NVCC) -O3 -arch=$(ARCH) $< -o $@

$(TEST_BIN): cuda/test_blake3.cpp cuda/blake3_64.cuh
	$(CXX) -O2 -x c++ $< -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

rust:
	cargo build --release
	cargo build --release --manifest-path mail-vanity/Cargo.toml

rust-test:
	cargo test --release
	cargo test --release --manifest-path mail-vanity/Cargo.toml

venv:
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -r requirements.txt

clean:
	rm -f $(GPU_BIN) $(TEST_BIN)
