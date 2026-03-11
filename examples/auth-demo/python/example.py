from __future__ import annotations

import json

from tafrah import TafrahABI


def main() -> int:
    abi = TafrahABI()
    ek, dk = abi.ml_kem_768_keygen()
    ct, client_ss = abi.ml_kem_768_encapsulate(ek)
    server_ss = abi.ml_kem_768_decapsulate(dk, ct)

    hqc_ek, hqc_dk = abi.hqc_128_keygen()
    hqc_ct, hqc_client_ss = abi.hqc_128_encapsulate(hqc_ek)
    hqc_server_ss = abi.hqc_128_decapsulate(hqc_dk, hqc_ct)

    ml_msg = b"tafrah-auth-demo::ml-dsa-65"
    ml_vk, ml_sk = abi.ml_dsa_65_keygen()
    ml_sig = abi.ml_dsa_65_sign(ml_sk, ml_msg)

    slh_msg = b"tafrah-auth-demo::slh-dsa-shake-128f"
    slh_vk, slh_sk = abi.slh_dsa_shake_128f_keygen()
    slh_sig = abi.slh_dsa_shake_128f_sign(slh_sk, slh_msg)

    falcon_msg = b"tafrah-auth-demo::falcon-512"
    falcon_vk, falcon_sk = abi.falcon_512_keygen()
    falcon_sig = abi.falcon_512_sign(falcon_sk, falcon_msg)

    result = {
        "language": "python",
        "native_version": abi.version,
        "ml_kem_768_shared_secret_match": client_ss == server_ss,
        "hqc_128_shared_secret_match": hqc_client_ss == hqc_server_ss,
        "ml_dsa_65_verify_ok": abi.ml_dsa_65_verify(ml_vk, ml_msg, ml_sig),
        "ml_dsa_65_tamper_rejected": not abi.ml_dsa_65_verify(ml_vk, ml_msg + b"\x01", ml_sig),
        "slh_dsa_shake_128f_verify_ok": abi.slh_dsa_shake_128f_verify(slh_vk, slh_msg, slh_sig),
        "slh_dsa_shake_128f_tamper_rejected": not abi.slh_dsa_shake_128f_verify(
            slh_vk, slh_msg + b"\x02", slh_sig
        ),
        "falcon_512_verify_ok": abi.falcon_512_verify(falcon_vk, falcon_msg, falcon_sig),
        "falcon_512_tamper_rejected": not abi.falcon_512_verify(
            falcon_vk, falcon_msg + b"\x03", falcon_sig
        ),
    }
    result["overall_ok"] = all(
        result[key]
        for key in (
            "ml_kem_768_shared_secret_match",
            "hqc_128_shared_secret_match",
            "ml_dsa_65_verify_ok",
            "ml_dsa_65_tamper_rejected",
            "slh_dsa_shake_128f_verify_ok",
            "slh_dsa_shake_128f_tamper_rejected",
            "falcon_512_verify_ok",
            "falcon_512_tamper_rejected",
        )
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["overall_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
