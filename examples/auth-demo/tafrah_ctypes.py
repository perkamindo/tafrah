from __future__ import annotations

import ctypes
import os
import platform
import subprocess
from pathlib import Path


class TafrahAbiError(RuntimeError):
    pass


class TafrahABI:
    STATUS_OK = 0
    STATUS_NULL_POINTER = 1
    STATUS_INVALID_LENGTH = 2
    STATUS_INVALID_PARAMETER = 3
    STATUS_VERIFICATION_FAILED = 4
    STATUS_INTERNAL_ERROR = 5

    def __init__(self, library_path: Path | None = None, auto_build: bool = True) -> None:
        self._workspace_root = Path(__file__).resolve().parents[2]
        install_prefix = os.environ.get("TAFRAH_INSTALL_PREFIX")
        explicit_library_path = library_path is not None
        self._library_path = Path(library_path) if explicit_library_path else self.default_library_path()
        if auto_build and not explicit_library_path and not install_prefix:
            # Repo-local proof runs should not silently reuse a stale ABI build.
            self.build_native()
            self._library_path = self.default_library_path()
        elif auto_build and not self._library_path.exists():
            self.build_native()
            self._library_path = self.default_library_path()
        self._lib = ctypes.CDLL(str(self._library_path))
        self._bind()

        self.version = self._lib.tafrah_version().decode()
        self.ml_kem_768_ek_size = self._lib.tafrah_ml_kem_768_ek_size()
        self.ml_kem_768_dk_size = self._lib.tafrah_ml_kem_768_dk_size()
        self.ml_kem_768_ct_size = self._lib.tafrah_ml_kem_768_ct_size()
        self.shared_secret_size = self._lib.tafrah_shared_secret_size()
        self.ml_dsa_65_vk_size = self._lib.tafrah_ml_dsa_65_vk_size()
        self.ml_dsa_65_sk_size = self._lib.tafrah_ml_dsa_65_sk_size()
        self.ml_dsa_65_sig_size = self._lib.tafrah_ml_dsa_65_sig_size()
        self.slh_dsa_shake_128f_vk_size = self._lib.tafrah_slh_dsa_shake_128f_vk_size()
        self.slh_dsa_shake_128f_sk_size = self._lib.tafrah_slh_dsa_shake_128f_sk_size()
        self.slh_dsa_shake_128f_sig_size = self._lib.tafrah_slh_dsa_shake_128f_sig_size()
        self.falcon_512_vk_size = self._lib.tafrah_falcon_512_vk_size()
        self.falcon_512_sk_size = self._lib.tafrah_falcon_512_sk_size()
        self.falcon_512_sig_size = self._lib.tafrah_falcon_512_sig_size()
        self.hqc_128_ek_size = self._lib.tafrah_hqc_128_ek_size()
        self.hqc_128_dk_size = self._lib.tafrah_hqc_128_dk_size()
        self.hqc_128_ct_size = self._lib.tafrah_hqc_128_ct_size()
        self.hqc_128_ss_size = self._lib.tafrah_hqc_128_ss_size()

    @staticmethod
    def _suffix() -> str:
        system = platform.system()
        if system == "Darwin":
            return "dylib"
        if system == "Windows":
            return "dll"
        return "so"

    @staticmethod
    def _library_filename() -> str:
        if platform.system() == "Windows":
            return "tafrah_abi.dll"
        return f"libtafrah_abi.{TafrahABI._suffix()}"

    @staticmethod
    def _legacy_library_filename() -> str:
        if platform.system() == "Windows":
            return "tafrah_ffi.dll"
        return f"libtafrah_ffi.{TafrahABI._suffix()}"

    def default_library_path(self) -> Path:
        install_prefix = os.environ.get("TAFRAH_INSTALL_PREFIX")
        if install_prefix:
            root = Path(install_prefix) / "lib"
        else:
            root = self._workspace_root / "target" / "release"
        primary = root / self._library_filename()
        if primary.exists():
            return primary
        legacy = root / self._legacy_library_filename()
        return legacy if legacy.exists() else primary

    def build_native(self) -> None:
        subprocess.run(
            ["cargo", "build", "-p", "tafrah-abi", "--release"],
            cwd=self._workspace_root,
            check=True,
        )

    def _bind(self) -> None:
        u8p = ctypes.POINTER(ctypes.c_ubyte)
        size_t = ctypes.c_size_t

        self._lib.tafrah_version.restype = ctypes.c_char_p
        self._lib.tafrah_status_string.argtypes = [ctypes.c_int]
        self._lib.tafrah_status_string.restype = ctypes.c_char_p

        for name in (
            "tafrah_ml_kem_768_ek_size",
            "tafrah_ml_kem_768_dk_size",
            "tafrah_ml_kem_768_ct_size",
            "tafrah_shared_secret_size",
            "tafrah_ml_dsa_65_vk_size",
            "tafrah_ml_dsa_65_sk_size",
            "tafrah_ml_dsa_65_sig_size",
            "tafrah_slh_dsa_shake_128f_vk_size",
            "tafrah_slh_dsa_shake_128f_sk_size",
            "tafrah_slh_dsa_shake_128f_sig_size",
            "tafrah_falcon_512_vk_size",
            "tafrah_falcon_512_sk_size",
            "tafrah_falcon_512_sig_size",
            "tafrah_hqc_128_ek_size",
            "tafrah_hqc_128_dk_size",
            "tafrah_hqc_128_ct_size",
            "tafrah_hqc_128_ss_size",
        ):
            getattr(self._lib, name).restype = size_t

        self._lib.tafrah_ml_kem_768_keygen.argtypes = [u8p, size_t, u8p, size_t]
        self._lib.tafrah_ml_kem_768_keygen.restype = ctypes.c_int
        self._lib.tafrah_ml_kem_768_encapsulate.argtypes = [u8p, size_t, u8p, size_t, u8p, size_t]
        self._lib.tafrah_ml_kem_768_encapsulate.restype = ctypes.c_int
        self._lib.tafrah_ml_kem_768_decapsulate.argtypes = [u8p, size_t, u8p, size_t, u8p, size_t]
        self._lib.tafrah_ml_kem_768_decapsulate.restype = ctypes.c_int

        self._lib.tafrah_ml_dsa_65_keygen.argtypes = [u8p, size_t, u8p, size_t]
        self._lib.tafrah_ml_dsa_65_keygen.restype = ctypes.c_int
        self._lib.tafrah_ml_dsa_65_sign.argtypes = [u8p, size_t, u8p, size_t, u8p, size_t]
        self._lib.tafrah_ml_dsa_65_sign.restype = ctypes.c_int
        self._lib.tafrah_ml_dsa_65_verify.argtypes = [u8p, size_t, u8p, size_t, u8p, size_t]
        self._lib.tafrah_ml_dsa_65_verify.restype = ctypes.c_int

        self._lib.tafrah_slh_dsa_shake_128f_keygen.argtypes = [u8p, size_t, u8p, size_t]
        self._lib.tafrah_slh_dsa_shake_128f_keygen.restype = ctypes.c_int
        self._lib.tafrah_slh_dsa_shake_128f_sign.argtypes = [u8p, size_t, u8p, size_t, u8p, size_t]
        self._lib.tafrah_slh_dsa_shake_128f_sign.restype = ctypes.c_int
        self._lib.tafrah_slh_dsa_shake_128f_verify.argtypes = [u8p, size_t, u8p, size_t, u8p, size_t]
        self._lib.tafrah_slh_dsa_shake_128f_verify.restype = ctypes.c_int
        self._lib.tafrah_slh_dsa_shake_128f_hash_sha2_256_sign.argtypes = [u8p, size_t, u8p, size_t, u8p, size_t]
        self._lib.tafrah_slh_dsa_shake_128f_hash_sha2_256_sign.restype = ctypes.c_int
        self._lib.tafrah_slh_dsa_shake_128f_hash_sha2_256_verify.argtypes = [u8p, size_t, u8p, size_t, u8p, size_t]
        self._lib.tafrah_slh_dsa_shake_128f_hash_sha2_256_verify.restype = ctypes.c_int

        self._lib.tafrah_falcon_512_keygen.argtypes = [u8p, size_t, u8p, size_t]
        self._lib.tafrah_falcon_512_keygen.restype = ctypes.c_int
        self._lib.tafrah_falcon_512_sign.argtypes = [u8p, size_t, u8p, size_t, u8p, size_t, ctypes.POINTER(size_t)]
        self._lib.tafrah_falcon_512_sign.restype = ctypes.c_int
        self._lib.tafrah_falcon_512_verify.argtypes = [u8p, size_t, u8p, size_t, u8p, size_t]
        self._lib.tafrah_falcon_512_verify.restype = ctypes.c_int

        self._lib.tafrah_hqc_128_keygen.argtypes = [u8p, size_t, u8p, size_t]
        self._lib.tafrah_hqc_128_keygen.restype = ctypes.c_int
        self._lib.tafrah_hqc_128_encapsulate.argtypes = [u8p, size_t, u8p, size_t, u8p, size_t]
        self._lib.tafrah_hqc_128_encapsulate.restype = ctypes.c_int
        self._lib.tafrah_hqc_128_decapsulate.argtypes = [u8p, size_t, u8p, size_t, u8p, size_t]
        self._lib.tafrah_hqc_128_decapsulate.restype = ctypes.c_int

    @staticmethod
    def _ubyte_array(data: bytes):
        if not data:
            return None
        return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)

    @staticmethod
    def _out_buffer(size: int):
        return (ctypes.c_ubyte * size)()

    @staticmethod
    def _as_bytes(buffer) -> bytes:
        return bytes(buffer)

    def status_text(self, status: int) -> str:
        return self._lib.tafrah_status_string(status).decode()

    def _check(self, status: int) -> None:
        if status != self.STATUS_OK:
            raise TafrahAbiError(f"native call failed: {status} ({self.status_text(status)})")

    def _verify_result(self, status: int) -> bool:
        if status == self.STATUS_OK:
            return True
        if status == self.STATUS_VERIFICATION_FAILED:
            return False
        raise TafrahAbiError(f"native verify failed: {status} ({self.status_text(status)})")

    def _expect_status(self, status: int, expected: int, op: str) -> bool:
        if status == expected:
            return True
        raise TafrahAbiError(
            f"{op}: expected {expected} ({self.status_text(expected)}), "
            f"got {status} ({self.status_text(status)})"
        )

    def expect_status(self, status: int, expected: int, op: str) -> bool:
        return self._expect_status(status, expected, op)

    def ml_kem_768_keygen(self) -> tuple[bytes, bytes]:
        ek = self._out_buffer(self.ml_kem_768_ek_size)
        dk = self._out_buffer(self.ml_kem_768_dk_size)
        self._check(self._lib.tafrah_ml_kem_768_keygen(ek, len(ek), dk, len(dk)))
        return self._as_bytes(ek), self._as_bytes(dk)

    def ml_kem_768_encapsulate(self, ek: bytes) -> tuple[bytes, bytes]:
        ek_in = self._ubyte_array(ek)
        ct = self._out_buffer(self.ml_kem_768_ct_size)
        ss = self._out_buffer(self.shared_secret_size)
        self._check(
            self._lib.tafrah_ml_kem_768_encapsulate(
                ek_in, len(ek), ct, len(ct), ss, len(ss)
            )
        )
        return self._as_bytes(ct), self._as_bytes(ss)

    def ml_kem_768_decapsulate(self, dk: bytes, ct: bytes) -> bytes:
        dk_in = self._ubyte_array(dk)
        ct_in = self._ubyte_array(ct)
        ss = self._out_buffer(self.shared_secret_size)
        self._check(
            self._lib.tafrah_ml_kem_768_decapsulate(
                dk_in, len(dk), ct_in, len(ct), ss, len(ss)
            )
        )
        return self._as_bytes(ss)

    def ml_kem_768_decapsulate_status(self, dk: bytes, ct: bytes) -> int:
        dk_in = self._ubyte_array(dk)
        ct_in = self._ubyte_array(ct)
        ss = self._out_buffer(self.shared_secret_size)
        return self._lib.tafrah_ml_kem_768_decapsulate(
            dk_in, len(dk), ct_in, len(ct), ss, len(ss)
        )

    def ml_dsa_65_keygen(self) -> tuple[bytes, bytes]:
        vk = self._out_buffer(self.ml_dsa_65_vk_size)
        sk = self._out_buffer(self.ml_dsa_65_sk_size)
        self._check(self._lib.tafrah_ml_dsa_65_keygen(vk, len(vk), sk, len(sk)))
        return self._as_bytes(vk), self._as_bytes(sk)

    def ml_dsa_65_sign(self, sk: bytes, message: bytes) -> bytes:
        sk_in = self._ubyte_array(sk)
        msg_in = self._ubyte_array(message)
        sig = self._out_buffer(self.ml_dsa_65_sig_size)
        self._check(
            self._lib.tafrah_ml_dsa_65_sign(
                sk_in, len(sk), msg_in, len(message), sig, len(sig)
            )
        )
        return self._as_bytes(sig)

    def ml_dsa_65_verify(self, vk: bytes, message: bytes, sig: bytes) -> bool:
        vk_in = self._ubyte_array(vk)
        msg_in = self._ubyte_array(message)
        sig_in = self._ubyte_array(sig)
        return self._verify_result(
            self._lib.tafrah_ml_dsa_65_verify(
                vk_in, len(vk), msg_in, len(message), sig_in, len(sig)
            )
        )

    def ml_dsa_65_verify_status(self, vk: bytes, message: bytes, sig: bytes) -> int:
        vk_in = self._ubyte_array(vk)
        msg_in = self._ubyte_array(message)
        sig_in = self._ubyte_array(sig)
        return self._lib.tafrah_ml_dsa_65_verify(
            vk_in, len(vk), msg_in, len(message), sig_in, len(sig)
        )

    def slh_dsa_shake_128f_keygen(self) -> tuple[bytes, bytes]:
        vk = self._out_buffer(self.slh_dsa_shake_128f_vk_size)
        sk = self._out_buffer(self.slh_dsa_shake_128f_sk_size)
        self._check(
            self._lib.tafrah_slh_dsa_shake_128f_keygen(vk, len(vk), sk, len(sk))
        )
        return self._as_bytes(vk), self._as_bytes(sk)

    def slh_dsa_shake_128f_sign(self, sk: bytes, message: bytes) -> bytes:
        sk_in = self._ubyte_array(sk)
        msg_in = self._ubyte_array(message)
        sig = self._out_buffer(self.slh_dsa_shake_128f_sig_size)
        self._check(
            self._lib.tafrah_slh_dsa_shake_128f_sign(
                sk_in, len(sk), msg_in, len(message), sig, len(sig)
            )
        )
        return self._as_bytes(sig)

    def slh_dsa_shake_128f_verify(self, vk: bytes, message: bytes, sig: bytes) -> bool:
        vk_in = self._ubyte_array(vk)
        msg_in = self._ubyte_array(message)
        sig_in = self._ubyte_array(sig)
        return self._verify_result(
            self._lib.tafrah_slh_dsa_shake_128f_verify(
                vk_in, len(vk), msg_in, len(message), sig_in, len(sig)
            )
        )

    def slh_dsa_shake_128f_verify_status(self, vk: bytes, message: bytes, sig: bytes) -> int:
        vk_in = self._ubyte_array(vk)
        msg_in = self._ubyte_array(message)
        sig_in = self._ubyte_array(sig)
        return self._lib.tafrah_slh_dsa_shake_128f_verify(
            vk_in, len(vk), msg_in, len(message), sig_in, len(sig)
        )

    def slh_dsa_shake_128f_hash_sha2_256_sign(self, sk: bytes, message: bytes) -> bytes:
        sk_in = self._ubyte_array(sk)
        msg_in = self._ubyte_array(message)
        sig = self._out_buffer(self.slh_dsa_shake_128f_sig_size)
        self._check(
            self._lib.tafrah_slh_dsa_shake_128f_hash_sha2_256_sign(
                sk_in, len(sk), msg_in, len(message), sig, len(sig)
            )
        )
        return self._as_bytes(sig)

    def slh_dsa_shake_128f_hash_sha2_256_verify(
        self, vk: bytes, message: bytes, sig: bytes
    ) -> bool:
        vk_in = self._ubyte_array(vk)
        msg_in = self._ubyte_array(message)
        sig_in = self._ubyte_array(sig)
        return self._verify_result(
            self._lib.tafrah_slh_dsa_shake_128f_hash_sha2_256_verify(
                vk_in, len(vk), msg_in, len(message), sig_in, len(sig)
            )
        )

    def hqc_128_keygen(self) -> tuple[bytes, bytes]:
        ek = self._out_buffer(self.hqc_128_ek_size)
        dk = self._out_buffer(self.hqc_128_dk_size)
        self._check(self._lib.tafrah_hqc_128_keygen(ek, len(ek), dk, len(dk)))
        return self._as_bytes(ek), self._as_bytes(dk)

    def hqc_128_encapsulate(self, ek: bytes) -> tuple[bytes, bytes]:
        ek_in = self._ubyte_array(ek)
        ct = self._out_buffer(self.hqc_128_ct_size)
        ss = self._out_buffer(self.hqc_128_ss_size)
        self._check(
            self._lib.tafrah_hqc_128_encapsulate(
                ek_in, len(ek), ct, len(ct), ss, len(ss)
            )
        )
        return self._as_bytes(ct), self._as_bytes(ss)

    def hqc_128_decapsulate(self, dk: bytes, ct: bytes) -> bytes:
        dk_in = self._ubyte_array(dk)
        ct_in = self._ubyte_array(ct)
        ss = self._out_buffer(self.hqc_128_ss_size)
        self._check(
            self._lib.tafrah_hqc_128_decapsulate(
                dk_in, len(dk), ct_in, len(ct), ss, len(ss)
            )
        )
        return self._as_bytes(ss)

    def hqc_128_decapsulate_status(self, dk: bytes, ct: bytes) -> int:
        dk_in = self._ubyte_array(dk)
        ct_in = self._ubyte_array(ct)
        ss = self._out_buffer(self.hqc_128_ss_size)
        return self._lib.tafrah_hqc_128_decapsulate(
            dk_in, len(dk), ct_in, len(ct), ss, len(ss)
        )

    def falcon_512_keygen(self) -> tuple[bytes, bytes]:
        vk = self._out_buffer(self.falcon_512_vk_size)
        sk = self._out_buffer(self.falcon_512_sk_size)
        self._check(self._lib.tafrah_falcon_512_keygen(vk, len(vk), sk, len(sk)))
        return self._as_bytes(vk), self._as_bytes(sk)

    def falcon_512_sign(self, sk: bytes, message: bytes) -> bytes:
        sk_in = self._ubyte_array(sk)
        msg_in = self._ubyte_array(message)
        sig = self._out_buffer(self.falcon_512_sig_size)
        sig_written = ctypes.c_size_t()
        self._check(
            self._lib.tafrah_falcon_512_sign(
                sk_in, len(sk), msg_in, len(message), sig, len(sig), ctypes.byref(sig_written)
            )
        )
        return self._as_bytes(sig)[: sig_written.value]

    def falcon_512_verify(self, vk: bytes, message: bytes, sig: bytes) -> bool:
        vk_in = self._ubyte_array(vk)
        msg_in = self._ubyte_array(message)
        sig_in = self._ubyte_array(sig)
        return self._verify_result(
            self._lib.tafrah_falcon_512_verify(
                vk_in, len(vk), msg_in, len(message), sig_in, len(sig)
            )
        )

    def falcon_512_verify_status(self, vk: bytes, message: bytes, sig: bytes) -> int:
        vk_in = self._ubyte_array(vk)
        msg_in = self._ubyte_array(message)
        sig_in = self._ubyte_array(sig)
        return self._lib.tafrah_falcon_512_verify(
            vk_in, len(vk), msg_in, len(message), sig_in, len(sig)
        )


TafrahError = TafrahAbiError
TafrahFFI = TafrahABI
