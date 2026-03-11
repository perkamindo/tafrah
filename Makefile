SHELL := /bin/sh

PREFIX ?= $(CURDIR)/dist/install
UNIFFI_LANGUAGE ?= python
UNIFFI_OUT_DIR ?= $(CURDIR)/target/uniffi/$(UNIFFI_LANGUAGE)

.PHONY: help test test-reference test-deep-slh build build-abi build-ffi build-uniffi install install-abi install-ffi examples demo-examples demo-python generate-uniffi

help:
	@printf '%s\n' \
		'targets:' \
		'  make test                 - run full workspace test suite' \
		'  make test-reference       - run default reference oracle suite' \
		'  make test-deep-slh        - run expensive current-reference SLH-DSA audit' \
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

test-deep-slh:
	cargo test -p tafrah --test reference_kat test_reference_slh_dsa_sphincs_master_detkat_selected_deep_counts -- --ignored

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
