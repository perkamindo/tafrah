#ifndef TAFRAH_AUTH_DEMO_DEMO_CORE_HPP
#define TAFRAH_AUTH_DEMO_DEMO_CORE_HPP

#include <string>

namespace tafrah_demo {

struct DemoResult {
  std::string native_version;
  bool ml_kem_768_shared_secret_match;
  bool ml_kem_768_truncated_ct_rejected;
  bool symmetric_roundtrip_ok;
  bool hash_sha256_ok;
  bool hqc_128_shared_secret_match;
  bool hqc_128_truncated_ct_rejected;
  bool ml_dsa_65_verify_ok;
  bool ml_dsa_65_tamper_rejected;
  bool ml_dsa_65_truncated_sig_rejected;
  bool slh_dsa_shake_128f_verify_ok;
  bool slh_dsa_shake_128f_prehash_verify_ok;
  bool slh_dsa_shake_128f_prehash_tamper_rejected;
  bool slh_dsa_shake_128f_tamper_rejected;
  bool slh_dsa_shake_128f_truncated_sig_rejected;
  bool falcon_512_verify_ok;
  bool falcon_512_tamper_rejected;
  bool falcon_512_truncated_sig_rejected;
  bool ok;
};

DemoResult run_demo();
std::string result_to_json(const DemoResult& result, const std::string& language);

}  // namespace tafrah_demo

#endif
