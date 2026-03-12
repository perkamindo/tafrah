from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from tafrah_ctypes import TafrahABI


ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def encode_parts(*parts: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        out.extend(len(part).to_bytes(4, "big"))
        out.extend(part)
    return bytes(out)


def hkdf_sha3_256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.digest(salt, ikm, "sha3_256")
    okm = bytearray()
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.digest(prk, block + info + bytes([counter]), "sha3_256")
        okm.extend(block)
        counter += 1
    return bytes(okm[:length])


def derive_transport_keys(shared_secret: bytes) -> dict[str, bytes]:
    material = hkdf_sha3_256(
        shared_secret,
        b"tafrah-auth-demo::transport-salt",
        encode_parts(b"tafrah-auth-demo::transport"),
        128,
    )
    return {
        "client_enc": material[0:32],
        "client_mac": material[32:64],
        "server_enc": material[64:96],
        "server_mac": material[96:128],
    }


def derive_file_keys(shared_secret: bytes) -> dict[str, bytes]:
    material = hkdf_sha3_256(
        shared_secret,
        b"tafrah-auth-demo::file-salt",
        encode_parts(b"tafrah-auth-demo::file"),
        64,
    )
    return {
        "enc": material[0:32],
        "mac": material[32:64],
    }


def stream_xor(key: bytes, nonce: bytes, label: bytes, data: bytes) -> bytes:
    stream = hkdf_sha3_256(
        key,
        b"tafrah-auth-demo::stream-salt",
        encode_parts(b"tafrah-auth-demo::stream", label, nonce),
        len(data),
    )
    return bytes(a ^ b for a, b in zip(data, stream))


def seal(enc_key: bytes, mac_key: bytes, aad: bytes, plaintext: bytes) -> dict[str, str]:
    nonce = os.urandom(16)
    ciphertext = stream_xor(enc_key, nonce, b"tafrah-auth-demo::stream", plaintext)
    tag = hmac.digest(mac_key, aad + nonce + ciphertext, "sha3_256")
    return {
        "nonce": b64(nonce),
        "ciphertext": b64(ciphertext),
        "tag": b64(tag),
    }


def open_box(enc_key: bytes, mac_key: bytes, aad: bytes, package: dict[str, str]) -> bytes:
    nonce = base64.b64decode(package["nonce"])
    ciphertext = base64.b64decode(package["ciphertext"])
    expected_tag = base64.b64decode(package["tag"])
    actual_tag = hmac.digest(mac_key, aad + nonce + ciphertext, "sha3_256")
    if not hmac.compare_digest(expected_tag, actual_tag):
        raise ValueError("integrity check failed")
    return stream_xor(enc_key, nonce, b"tafrah-auth-demo::stream", ciphertext)


@dataclass
class Benchmark:
    label: str
    repeat: int
    average_ms: float


def benchmark(label: str, repeat: int, operation) -> Benchmark:
    start = perf_counter()
    for _ in range(repeat):
        operation()
    elapsed_ms = (perf_counter() - start) * 1000.0
    return Benchmark(label=label, repeat=repeat, average_ms=elapsed_ms / repeat)


def run_chat_proof(abi: TafrahABI) -> dict[str, object]:
    server_ek, server_dk = abi.ml_kem_768_keygen()
    kem_ct, client_ss = abi.ml_kem_768_encapsulate(server_ek)
    server_ss = abi.ml_kem_768_decapsulate(server_dk, kem_ct)
    assert hmac.compare_digest(client_ss, server_ss)

    keys = derive_transport_keys(client_ss)

    client_plaintext = b"client->server: pqc chat session established"
    client_box = seal(keys["client_enc"], keys["client_mac"], b"client->server", client_plaintext)
    server_received = open_box(
        keys["client_enc"], keys["client_mac"], b"client->server", client_box
    )
    assert server_received == client_plaintext

    server_plaintext = b"server->client: ack, transcript verified"
    server_box = seal(keys["server_enc"], keys["server_mac"], b"server->client", server_plaintext)
    client_received = open_box(
        keys["server_enc"], keys["server_mac"], b"server->client", server_box
    )
    assert client_received == server_plaintext

    transcript = json.dumps(
        {
            "kem_ct": b64(kem_ct),
            "client_box": client_box,
            "server_box": server_box,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return {
        "shared_secret_match": hmac.compare_digest(client_ss, server_ss),
        "kem_ciphertext_bytes": len(kem_ct),
        "client_message": server_received.decode("utf-8"),
        "server_message": client_received.decode("utf-8"),
        "transcript": transcript,
    }


def run_file_proof(abi: TafrahABI) -> dict[str, object]:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    plaintext_path = ARTIFACTS_DIR / "sample_plaintext.txt"
    encrypted_path = ARTIFACTS_DIR / "sample_plaintext.tafrah.json"
    recovered_path = ARTIFACTS_DIR / "sample_plaintext.recovered.txt"

    plaintext = (
        b"Tafrah proof-of-use file.\n"
        b"This demonstrates ML-KEM derived encryption from a foreign-language caller.\n"
        b"Integrity is enforced with HMAC-SHA3-256 inside the Python proof layer.\n"
    )
    plaintext_path.write_bytes(plaintext)

    recipient_ek, recipient_dk = abi.ml_kem_768_keygen()
    kem_ct, sender_ss = abi.ml_kem_768_encapsulate(recipient_ek)
    recipient_ss = abi.ml_kem_768_decapsulate(recipient_dk, kem_ct)
    assert hmac.compare_digest(sender_ss, recipient_ss)

    keys = derive_file_keys(sender_ss)
    package = seal(keys["enc"], keys["mac"], b"file::sample_plaintext.txt", plaintext)
    package["kem_ct"] = b64(kem_ct)
    package["plaintext_sha3_256"] = hashlib.sha3_256(plaintext).hexdigest()
    encrypted_path.write_text(json.dumps(package, indent=2, sort_keys=True))

    recovered = open_box(keys["enc"], keys["mac"], b"file::sample_plaintext.txt", package)
    recovered_path.write_bytes(recovered)
    assert recovered == plaintext

    return {
        "plaintext_path": str(plaintext_path),
        "encrypted_path": str(encrypted_path),
        "recovered_path": str(recovered_path),
        "ciphertext_bytes": len(base64.b64decode(package["ciphertext"])),
        "kem_ciphertext_bytes": len(kem_ct),
        "sha3_256": package["plaintext_sha3_256"],
    }


def run_signature_proof(abi: TafrahABI, transcript: bytes, file_digest_hex: str) -> dict[str, object]:
    ml_dsa_vk, ml_dsa_sk = abi.ml_dsa_65_keygen()
    slh_vk, slh_sk = abi.slh_dsa_shake_128f_keygen()
    falcon_vk, falcon_sk = abi.falcon_512_keygen()

    ml_dsa_message = hashlib.sha3_256(transcript).digest()
    slh_message = bytes.fromhex(file_digest_hex)
    falcon_message = hashlib.sha3_256(b"falcon::" + transcript).digest()

    ml_dsa_sig = abi.ml_dsa_65_sign(ml_dsa_sk, ml_dsa_message)
    assert abi.ml_dsa_65_verify(ml_dsa_vk, ml_dsa_message, ml_dsa_sig)
    assert not abi.ml_dsa_65_verify(ml_dsa_vk, ml_dsa_message + b"\x01", ml_dsa_sig)

    slh_sig = abi.slh_dsa_shake_128f_sign(slh_sk, slh_message)
    assert abi.slh_dsa_shake_128f_verify(slh_vk, slh_message, slh_sig)
    assert not abi.slh_dsa_shake_128f_verify(slh_vk, slh_message + b"\x02", slh_sig)

    falcon_sig = abi.falcon_512_sign(falcon_sk, falcon_message)
    assert abi.falcon_512_verify(falcon_vk, falcon_message, falcon_sig)
    assert not abi.falcon_512_verify(falcon_vk, falcon_message + b"\x03", falcon_sig)

    return {
        "ml_dsa_sig_bytes": len(ml_dsa_sig),
        "slh_dsa_sig_bytes": len(slh_sig),
        "falcon_512_sig_bytes": len(falcon_sig),
        "ml_dsa_verify_ok": True,
        "ml_dsa_tamper_rejected": True,
        "slh_dsa_verify_ok": True,
        "slh_dsa_tamper_rejected": True,
        "falcon_512_verify_ok": True,
        "falcon_512_tamper_rejected": True,
    }


def run_benchmarks(abi: TafrahABI) -> list[Benchmark]:
    kem_ek, kem_dk = abi.ml_kem_768_keygen()
    kem_ct, _ = abi.ml_kem_768_encapsulate(kem_ek)

    ml_vk, ml_sk = abi.ml_dsa_65_keygen()
    ml_msg = hashlib.sha3_256(b"tafrah benchmark ml-dsa").digest()
    ml_sig = abi.ml_dsa_65_sign(ml_sk, ml_msg)

    slh_vk, slh_sk = abi.slh_dsa_shake_128f_keygen()
    slh_msg = hashlib.sha3_256(b"tafrah benchmark slh-dsa").digest()
    slh_sig = abi.slh_dsa_shake_128f_sign(slh_sk, slh_msg)

    falcon_vk, falcon_sk = abi.falcon_512_keygen()
    falcon_msg = hashlib.sha3_256(b"tafrah benchmark falcon").digest()
    falcon_sig = abi.falcon_512_sign(falcon_sk, falcon_msg)

    return [
        benchmark("ml_kem_768_keygen", 10, abi.ml_kem_768_keygen),
        benchmark("ml_kem_768_encapsulate", 20, lambda: abi.ml_kem_768_encapsulate(kem_ek)),
        benchmark("ml_kem_768_decapsulate", 20, lambda: abi.ml_kem_768_decapsulate(kem_dk, kem_ct)),
        benchmark("ml_dsa_65_keygen", 5, abi.ml_dsa_65_keygen),
        benchmark("ml_dsa_65_sign", 10, lambda: abi.ml_dsa_65_sign(ml_sk, ml_msg)),
        benchmark("ml_dsa_65_verify", 20, lambda: abi.ml_dsa_65_verify(ml_vk, ml_msg, ml_sig)),
        benchmark("slh_dsa_shake_128f_keygen", 1, abi.slh_dsa_shake_128f_keygen),
        benchmark("slh_dsa_shake_128f_sign", 2, lambda: abi.slh_dsa_shake_128f_sign(slh_sk, slh_msg)),
        benchmark("slh_dsa_shake_128f_verify", 2, lambda: abi.slh_dsa_shake_128f_verify(slh_vk, slh_msg, slh_sig)),
        benchmark("falcon_512_keygen", 3, abi.falcon_512_keygen),
        benchmark("falcon_512_sign", 5, lambda: abi.falcon_512_sign(falcon_sk, falcon_msg)),
        benchmark("falcon_512_verify", 10, lambda: abi.falcon_512_verify(falcon_vk, falcon_msg, falcon_sig)),
    ]


def print_report(abi: TafrahABI, chat: dict[str, object], file_proof: dict[str, object], sigs: dict[str, object], benches: list[Benchmark]) -> None:
    print("== Tafrah ctypes ABI proof ==")
    print(f"native_version: {abi.version}")
    print(f"library_path: {abi.default_library_path()}")
    print()

    print("== Correctness ==")
    print(f"shared_secret_match: {chat['shared_secret_match']}")
    print(f"chat_client_message: {chat['client_message']}")
    print(f"chat_server_message: {chat['server_message']}")
    print(f"file_sha3_256: {file_proof['sha3_256']}")
    print(f"ml_dsa_verify_ok: {sigs['ml_dsa_verify_ok']}")
    print(f"slh_dsa_verify_ok: {sigs['slh_dsa_verify_ok']}")
    print(f"falcon_512_verify_ok: {sigs['falcon_512_verify_ok']}")
    print()

    print("== Sizes ==")
    print(f"ml_kem_768_ct_bytes: {chat['kem_ciphertext_bytes']}")
    print(f"ml_dsa_65_sig_bytes: {sigs['ml_dsa_sig_bytes']}")
    print(f"slh_dsa_shake_128f_sig_bytes: {sigs['slh_dsa_sig_bytes']}")
    print(f"falcon_512_sig_bytes: {sigs['falcon_512_sig_bytes']}")
    print()

    print("== Benchmarks ==")
    for bench in benches:
        print(f"{bench.label}: avg_ms={bench.average_ms:.3f} repeat={bench.repeat}")
    print()

    print("== Assessment ==")
    print("correctness: native PQC primitives survive a foreign-language roundtrip and reject tampered signatures.")
    print("security: the ABI surface is fixed-size and explicit; the Python symmetric layer uses HMAC-SHA3-256 based derivation but remains proof-only, not a final production design.")
    print("maintainability: the ABI is intentionally narrow and maps directly to a small set of stable proof primitives.")
    print("developer_experience: no Python dependencies beyond stdlib, and the wrapper can auto-build the native library.")


def write_summary(abi: TafrahABI, chat: dict[str, object], file_proof: dict[str, object], sigs: dict[str, object], benches: list[Benchmark]) -> None:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    summary = {
        "native_version": abi.version,
        "correctness": {
            "shared_secret_match": chat["shared_secret_match"],
            "ml_dsa_verify_ok": sigs["ml_dsa_verify_ok"],
            "slh_dsa_verify_ok": sigs["slh_dsa_verify_ok"],
            "ml_dsa_tamper_rejected": sigs["ml_dsa_tamper_rejected"],
            "slh_dsa_tamper_rejected": sigs["slh_dsa_tamper_rejected"],
            "falcon_512_verify_ok": sigs["falcon_512_verify_ok"],
            "falcon_512_tamper_rejected": sigs["falcon_512_tamper_rejected"],
        },
        "artifacts": file_proof,
        "sizes": {
            "ml_kem_768_ct_bytes": chat["kem_ciphertext_bytes"],
            "ml_dsa_65_sig_bytes": sigs["ml_dsa_sig_bytes"],
            "slh_dsa_shake_128f_sig_bytes": sigs["slh_dsa_sig_bytes"],
            "falcon_512_sig_bytes": sigs["falcon_512_sig_bytes"],
        },
        "benchmarks_ms": {bench.label: round(bench.average_ms, 3) for bench in benches},
        "assessment": {
            "correctness": "Cross-language PQC operations succeed and tampering is rejected.",
            "security": "The ABI validates lengths explicitly; Python transport and file crypto remain proof-only.",
            "maintainability": "The ABI is narrow and maps one-to-one to the demo primitives.",
            "developer_experience": "Native build is a single cargo command and Python uses only ctypes + stdlib.",
        },
    }
    (ARTIFACTS_DIR / "proof_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))


def main() -> None:
    abi = TafrahABI(auto_build=True)
    chat = run_chat_proof(abi)
    file_proof = run_file_proof(abi)
    sigs = run_signature_proof(abi, chat["transcript"], file_proof["sha3_256"])
    benches = run_benchmarks(abi)
    print_report(abi, chat, file_proof, sigs, benches)
    write_summary(abi, chat, file_proof, sigs, benches)


if __name__ == "__main__":
    main()
