from __future__ import annotations

import hashlib
import hmac
import json

from tafrah import TafrahABI


def encode_parts(*parts: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        out.extend(len(part).to_bytes(4, "big"))
        out.extend(part)
    return bytes(out)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.digest(salt, ikm, "sha256")
    okm = bytearray()
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.digest(prk, block + info + bytes([counter]), "sha256")
        okm.extend(block)
        counter += 1
    return bytes(okm[:length])


def stream_xor(key: bytes, nonce: bytes, label: bytes, data: bytes) -> bytes:
    stream = hkdf_sha256(
        key,
        b"tafrah-auth-demo::stream-salt",
        encode_parts(b"tafrah-auth-demo::stream", label, nonce),
        len(data),
    )
    return bytes(a ^ b for a, b in zip(data, stream))


def main() -> int:
    abi = TafrahABI()
    ek, dk = abi.ml_kem_768_keygen()
    ct, client_ss = abi.ml_kem_768_encapsulate(ek)
    server_ss = abi.ml_kem_768_decapsulate(dk, ct)
    transport_material = hkdf_sha256(
        client_ss,
        b"tafrah-auth-demo::transport-salt",
        encode_parts(b"tafrah-auth-demo::transport"),
        64,
    )
    enc_key = transport_material[:32]
    nonce = hashlib.sha256(client_ss + b"tafrah-auth-demo::nonce").digest()[:16]
    plaintext = b"tafrah-auth-demo::symmetric-roundtrip"
    ciphertext = stream_xor(enc_key, nonce, b"client->server", plaintext)
    recovered = stream_xor(enc_key, nonce, b"client->server", ciphertext)
    hash_input = b"tafrah-auth-demo::hash::sha256"

    hqc_ek, hqc_dk = abi.hqc_128_keygen()
    hqc_ct, hqc_client_ss = abi.hqc_128_encapsulate(hqc_ek)
    hqc_server_ss = abi.hqc_128_decapsulate(hqc_dk, hqc_ct)

    ml_msg = b"tafrah-auth-demo::ml-dsa-65"
    ml_vk, ml_sk = abi.ml_dsa_65_keygen()
    ml_sig = abi.ml_dsa_65_sign(ml_sk, ml_msg)

    slh_msg = b"tafrah-auth-demo::slh-dsa-shake-128f"
    slh_vk, slh_sk = abi.slh_dsa_shake_128f_keygen()
    slh_sig = abi.slh_dsa_shake_128f_sign(slh_sk, slh_msg)
    slh_prehash_sig = abi.slh_dsa_shake_128f_hash_sha2_256_sign(slh_sk, slh_msg)

    falcon_msg = b"tafrah-auth-demo::falcon-512"
    falcon_vk, falcon_sk = abi.falcon_512_keygen()
    falcon_sig = abi.falcon_512_sign(falcon_sk, falcon_msg)

    result = {
        "language": "python",
        "native_version": abi.version,
        "ml_kem_768_shared_secret_match": hmac.compare_digest(client_ss, server_ss),
        "ml_kem_768_truncated_ct_rejected": abi.expect_status(
            abi.ml_kem_768_decapsulate_status(dk, ct[:-1]),
            abi.STATUS_INVALID_LENGTH,
            "tafrah_ml_kem_768_decapsulate_truncated",
        ),
        "symmetric_roundtrip_ok": hmac.compare_digest(plaintext, recovered),
        "hash_sha256_ok": hashlib.sha256(hash_input).hexdigest()
        == "5f36ca6b07d4d4a0162b71332eddefb1b79719d4719e09e2e880c059881ef00b",
        "hqc_128_shared_secret_match": hmac.compare_digest(hqc_client_ss, hqc_server_ss),
        "hqc_128_truncated_ct_rejected": abi.expect_status(
            abi.hqc_128_decapsulate_status(hqc_dk, hqc_ct[:-1]),
            abi.STATUS_INVALID_LENGTH,
            "tafrah_hqc_128_decapsulate_truncated",
        ),
        "ml_dsa_65_verify_ok": abi.ml_dsa_65_verify(ml_vk, ml_msg, ml_sig),
        "ml_dsa_65_tamper_rejected": not abi.ml_dsa_65_verify(ml_vk, ml_msg + b"\x01", ml_sig),
        "ml_dsa_65_truncated_sig_rejected": abi.expect_status(
            abi.ml_dsa_65_verify_status(ml_vk, ml_msg, ml_sig[:-1]),
            abi.STATUS_INVALID_LENGTH,
            "tafrah_ml_dsa_65_verify_truncated_sig",
        ),
        "slh_dsa_shake_128f_verify_ok": abi.slh_dsa_shake_128f_verify(slh_vk, slh_msg, slh_sig),
        "slh_dsa_shake_128f_prehash_verify_ok": abi.slh_dsa_shake_128f_hash_sha2_256_verify(
            slh_vk, slh_msg, slh_prehash_sig
        ),
        "slh_dsa_shake_128f_prehash_tamper_rejected": not abi.slh_dsa_shake_128f_hash_sha2_256_verify(
            slh_vk, slh_msg + b"\x04", slh_prehash_sig
        ),
        "slh_dsa_shake_128f_tamper_rejected": not abi.slh_dsa_shake_128f_verify(
            slh_vk, slh_msg + b"\x02", slh_sig
        ),
        "slh_dsa_shake_128f_truncated_sig_rejected": abi.expect_status(
            abi.slh_dsa_shake_128f_verify_status(slh_vk, slh_msg, slh_sig[:-1]),
            abi.STATUS_INVALID_LENGTH,
            "tafrah_slh_dsa_shake_128f_verify_truncated_sig",
        ),
        "falcon_512_verify_ok": abi.falcon_512_verify(falcon_vk, falcon_msg, falcon_sig),
        "falcon_512_tamper_rejected": not abi.falcon_512_verify(
            falcon_vk, falcon_msg + b"\x03", falcon_sig
        ),
        "falcon_512_truncated_sig_rejected": abi.expect_status(
            abi.falcon_512_verify_status(falcon_vk, falcon_msg, falcon_sig[:-1]),
            abi.STATUS_INVALID_LENGTH,
            "tafrah_falcon_512_verify_truncated_sig",
        ),
    }
    result["overall_ok"] = all(
        result[key]
        for key in (
            "ml_kem_768_shared_secret_match",
            "ml_kem_768_truncated_ct_rejected",
            "symmetric_roundtrip_ok",
            "hash_sha256_ok",
            "hqc_128_shared_secret_match",
            "hqc_128_truncated_ct_rejected",
            "ml_dsa_65_verify_ok",
            "ml_dsa_65_tamper_rejected",
            "ml_dsa_65_truncated_sig_rejected",
            "slh_dsa_shake_128f_verify_ok",
            "slh_dsa_shake_128f_prehash_verify_ok",
            "slh_dsa_shake_128f_prehash_tamper_rejected",
            "slh_dsa_shake_128f_tamper_rejected",
            "slh_dsa_shake_128f_truncated_sig_rejected",
            "falcon_512_verify_ok",
            "falcon_512_tamper_rejected",
            "falcon_512_truncated_sig_rejected",
        )
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["overall_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
