# C ABI

`tafrah-abi` provides the installable C ABI.

## Installed Headers

- `tafrah/tafrah.h`
- `tafrah/tafrah.hpp`
- `tafrah_abi.h`
- `tafrah_ffi.h` compatibility shim

## Install

```sh
make install PREFIX="$PWD/dist/install"
```

Then point your build system at:

- `dist/install/include`
- `dist/install/lib`
- `dist/install/lib/pkgconfig`

## Design Notes

- Caller-owned buffers are used throughout.
- Buffer lengths are validated explicitly.
- Status codes are stable and translated to strings by `tafrah_status_string`.
- Falcon detached signatures use `sig_capacity` plus `sig_written` because Falcon signatures are variable-length.

## Current Example Coverage

The example bundle currently exercises the ABI from:

- Python
- C++
- Go
- Java
- Kotlin
- JavaScript
