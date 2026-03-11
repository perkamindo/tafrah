#include <iostream>
#include <string>
#include <vector>

#include <tafrah/tafrah.hpp>

namespace {

std::string json_bool(bool value) {
  return value ? "true" : "false";
}

std::vector<uint8_t> bytes_from_text(const char* text) {
  const std::string value(text);
  return std::vector<uint8_t>(value.begin(), value.end());
}

}  // namespace

int main() {
  try {
    const auto kem = tafrah::ml_kem_768_keygen();
    const auto kem_enc = tafrah::ml_kem_768_encapsulate(kem.public_key);
    const auto kem_ss = tafrah::ml_kem_768_decapsulate(kem.secret_key, kem_enc.first);

    const auto hqc = tafrah::hqc_128_keygen();
    const auto hqc_enc = tafrah::hqc_128_encapsulate(hqc.public_key);
    const auto hqc_ss = tafrah::hqc_128_decapsulate(hqc.secret_key, hqc_enc.first);

    const auto ml_dsa = tafrah::ml_dsa_65_keygen();
    const auto ml_msg = bytes_from_text("tafrah-auth-demo::ml-dsa-65");
    const auto ml_sig = tafrah::ml_dsa_65_sign(ml_dsa.secret_key, ml_msg);
    auto ml_tampered = ml_msg;
    ml_tampered.push_back(1);

    const auto slh = tafrah::slh_dsa_shake_128f_keygen();
    const auto slh_msg = bytes_from_text("tafrah-auth-demo::slh-dsa-shake-128f");
    const auto slh_sig = tafrah::slh_dsa_shake_128f_sign(slh.secret_key, slh_msg);
    auto slh_tampered = slh_msg;
    slh_tampered.push_back(2);

    const auto falcon = tafrah::falcon_512_keygen();
    const auto falcon_msg = bytes_from_text("tafrah-auth-demo::falcon-512");
    const auto falcon_sig = tafrah::falcon_512_sign(falcon.secret_key, falcon_msg);
    auto falcon_tampered = falcon_msg;
    falcon_tampered.push_back(3);

    const bool ml_kem_ok = kem_enc.second == kem_ss;
    const bool hqc_ok = hqc_enc.second == hqc_ss;
    const bool ml_dsa_ok = tafrah::ml_dsa_65_verify(ml_dsa.public_key, ml_msg, ml_sig);
    const bool ml_dsa_tamper = !tafrah::ml_dsa_65_verify(ml_dsa.public_key, ml_tampered, ml_sig);
    const bool slh_ok = tafrah::slh_dsa_shake_128f_verify(slh.public_key, slh_msg, slh_sig);
    const bool slh_tamper = !tafrah::slh_dsa_shake_128f_verify(slh.public_key, slh_tampered, slh_sig);
    const bool falcon_ok = tafrah::falcon_512_verify(falcon.public_key, falcon_msg, falcon_sig);
    const bool falcon_tamper =
        !tafrah::falcon_512_verify(falcon.public_key, falcon_tampered, falcon_sig);
    const bool overall_ok =
        ml_kem_ok && hqc_ok && ml_dsa_ok && ml_dsa_tamper && slh_ok && slh_tamper && falcon_ok &&
        falcon_tamper;

    std::cout
        << "{\"language\":\"cpp\",\"native_version\":\"" << tafrah::version()
        << "\",\"ml_kem_768_shared_secret_match\":" << json_bool(ml_kem_ok)
        << ",\"hqc_128_shared_secret_match\":" << json_bool(hqc_ok)
        << ",\"ml_dsa_65_verify_ok\":" << json_bool(ml_dsa_ok)
        << ",\"ml_dsa_65_tamper_rejected\":" << json_bool(ml_dsa_tamper)
        << ",\"slh_dsa_shake_128f_verify_ok\":" << json_bool(slh_ok)
        << ",\"slh_dsa_shake_128f_tamper_rejected\":" << json_bool(slh_tamper)
        << ",\"falcon_512_verify_ok\":" << json_bool(falcon_ok)
        << ",\"falcon_512_tamper_rejected\":" << json_bool(falcon_tamper)
        << ",\"overall_ok\":" << json_bool(overall_ok) << "}" << std::endl;
    return overall_ok ? 0 : 1;
  } catch (const std::exception& err) {
    std::cerr << "cpp demo failed: " << err.what() << std::endl;
    return 1;
  }
}
