# UniFFI

`tafrah-uniffi` exists for higher-level host binding workflows.

## Build

```sh
make build-uniffi
```

## Generate Bindings

```sh
make generate-uniffi UNIFFI_LANGUAGE=python
```

Supported languages in the current generation workflow include:

- `python`
- `kotlin`
- `swift`

## Position in the Ecosystem

Use UniFFI when you want a higher-level host binding surface with generated glue code.

Use the C ABI when you want:

- maximum portability
- a stable install layout
- integration with existing non-Rust toolchains without binding generators
