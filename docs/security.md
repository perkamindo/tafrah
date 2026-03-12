# Security Notes

This document describes the current security posture of the Tafrah workspace.

## Threat Model

Tafrah is a native Rust PQC library focused on algorithmic correctness, serialized API stability, and hardening against malformed inputs.

The project currently aims to provide:

- correct FIPS-aligned implementations for the supported parameter sets
- explicit input-length validation on public entry points
- implicit rejection for ML-KEM decapsulation
- memory zeroization for serialized secret key carriers and selected temporary secret state

The project does not currently claim:

- resistance against all microarchitectural side channels
- comprehensive leakage assessment across all targets and compilers
- hardened deployment guidance for hostile multi-tenant environments

## Constant-Time Scope

Public decapsulation and verification paths are written to avoid obvious secret-dependent branching where the algorithm requires constant-time behavior.

This guarantee should be read narrowly:

- it applies to the implemented primitives and reviewed public paths
- it does not replace platform-specific side-channel review
- consumers are still responsible for secure key storage, process isolation, and transport security

## Falcon Floating-Point Limitation

Falcon relies on floating-point arithmetic as part of the standard algorithm design. Tafrah follows that design.

Implications:

- platforms should provide stable IEEE 754 floating-point behavior
- platform-specific rounding differences must be considered part of the deployment review
- portability to unusual floating-point environments should be validated before production use

## Pre-Standard Algorithms

FN-DSA (FIPS 206) and HQC (FIPS 207) have been selected by NIST, but the standards are not yet final.

Tafrah currently follows the available specifications and reference material. Behavior or serialized APIs may need to change when the final standards are published.
