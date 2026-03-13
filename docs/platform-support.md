# Platform Support

Tafrah has two distribution modes:

- prebuilt GitHub Release assets
- source builds from the repository or crates.io

## Prebuilt Release Assets

Prebuilt GitHub Release assets are architecture-specific. They are not
universal binaries.

The current release workflow targets:

- Linux `x86_64`
- Linux `aarch64`
- macOS `arm64`
- macOS `x86_64`
- Windows `x86_64`

Release asset names include both operating system and architecture so that the
packaging is explicit.

## Source Build Fallback

If no prebuilt asset matches the target machine, build from source from the
workspace root:

```sh
make test
make install PREFIX="$PWD/dist/install"
```

Rust consumers should usually use the native crates directly:

```sh
cargo add tafrah
```

Non-Rust consumers should prefer the installed ABI prefix from
`make install PREFIX=...`.

## Recommended Tooling

The following stack is a practical path for broader platform coverage:

- GitHub Actions hosted runners for release and validation:
  - `ubuntu-24.04`
  - `ubuntu-24.04-arm`
  - `macos-15`
  - `macos-15-intel`
  - `windows-latest`
- [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) for Linux
  cross-compilation from non-Linux hosts
- [`cross`](https://github.com/cross-rs/cross) for containerized cross builds
  and CI-friendly target coverage
- [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin) for Windows
  cross-compilation from macOS or Linux

For macOS, separate Intel and Apple Silicon runners remain the cleanest way to
produce native artifacts. A universal macOS package can be assembled later, but
the current release path prefers separate arch-specific assets because they are
easier to audit.
