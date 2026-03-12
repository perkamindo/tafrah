SHELL := /bin/sh

PREFIX ?= $(CURDIR)/dist/install
UNIFFI_LANGUAGE ?= python
UNIFFI_OUT_DIR ?= $(CURDIR)/target/uniffi/$(UNIFFI_LANGUAGE)

.PHONY: help test test-reference test-deep-slh test-deep-mldsa coverage build build-abi build-ffi build-uniffi install install-abi install-ffi examples demo-examples demo-python generate-uniffi bench bench-json

help:
	@printf '%s\n' \
		'targets:' \
		'  make test                 - run full workspace test suite' \
		'  make test-reference       - run default FIPS reference oracle suite' \
		'  make test-deep-slh        - run expensive FIPS 205 SPHINCS+ reference audit' \
		'  make test-deep-mldsa      - run expensive FIPS 204 ML-DSA reference audit' \
		'  make coverage             - run workspace coverage with cargo-llvm-cov' \
		'  make bench                - run native benchmark suite in table form' \
		'  make bench-json           - run native benchmark suite in JSON form' \
		'  make build                - build workspace debug artifacts' \
		'  make build-abi            - build release C ABI shared library' \
		'  make build-uniffi         - build release UniFFI shared library' \
		'  make install              - alias for make install-abi' \
		'  make install-abi          - install C ABI to PREFIX=$(PREFIX)' \
		'  make examples             - alias for make demo-examples' \
		'  make demo-examples        - run install-style language examples' \
		'  make demo-python          - run richer Python auth proof' \
		'  make generate-uniffi      - generate UniFFI bindings for UNIFFI_LANGUAGE=$(UNIFFI_LANGUAGE)'

test:
	cargo test

test-reference:
	cargo test -p tafrah --test reference_kat
	cargo test -p tafrah --test mldsa_native_reference

test-deep-slh:
	cargo test -p tafrah --test fips205_reference test_fips205_selected_deep_counts --release -- --ignored

test-deep-mldsa:
	cargo test -p tafrah --test mldsa_native_reference test_mldsa_native_feature_parity_all_counts --release -- --ignored

coverage:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "cargo-llvm-cov is required. Install it with: cargo install cargo-llvm-cov --locked"; exit 1; }
	rustup component add llvm-tools-preview
	cargo llvm-cov --workspace --all-features --html

bench:
	cargo run -p tafrah-bench --release

bench-avx2:
	cargo run -p tafrah-bench --release --features avx2

bench-neon:
	cargo run -p tafrah-bench --release --features neon

bench-json:
	cargo run -p tafrah-bench --release -- --json

bench-avx2-json:
	cargo run -p tafrah-bench --release --features avx2 -- --json

bench-neon-json:
	cargo run -p tafrah-bench --release --features neon -- --json

build:
	cargo build

build-abi:
	cargo build -p tafrah-abi --release

build-ffi: build-abi

build-uniffi:
	cargo build -p tafrah-uniffi --release

install: install-abi

install-abi:
	sh ./scripts/install-abi.sh "$(PREFIX)"

install-ffi: install-abi

examples: demo-examples

demo-examples:
	sh ./scripts/run-language-examples.sh

demo-python:
	python3 ./examples/auth-demo/proof_demo.py

generate-uniffi:
	sh ./scripts/generate-uniffi-bindings.sh "$(UNIFFI_LANGUAGE)" "$(UNIFFI_OUT_DIR)"
