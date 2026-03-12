#include "demo_core.hpp"

#include <stdexcept>
#include <string>
#include <vector>

#include <tafrah/tafrah.h>

namespace tafrah_demo {

namespace {

void check_status(int status, const char* op) {
  if (status != TAFRAH_STATUS_OK) {
    throw std::runtime_error(std::string(op) + ": " + tafrah_status_string(status));
  }
}

bool verify_result(int status, const char* op) {
  if (status == TAFRAH_STATUS_OK) {
    return true;
  }
  if (status == TAFRAH_STATUS_VERIFICATION_FAILED) {
    return false;
  }
  throw std::runtime_error(std::string(op) + ": " + tafrah_status_string(status));
}

std::string json_bool(bool value) {
  return value ? "true" : "false";
}

std::string escape_json(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (char ch : value) {
    switch (ch) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        out.push_back(ch);
        break;
    }
  }
  return out;
}

std::vector<uint8_t> bytes_from_text(const char* text) {
  const std::string value(text);
  return std::vector<uint8_t>(value.begin(), value.end());
}

bool constant_time_equal(const std::vector<uint8_t>& lhs, const std::vector<uint8_t>& rhs) {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  uint8_t diff = 0;
  for (size_t i = 0; i < lhs.size(); ++i) {
    diff |= lhs[i] ^ rhs[i];
  }
  return diff == 0;
}

void secure_zero(std::vector<uint8_t>& bytes) {
  volatile uint8_t* ptr = bytes.data();
  for (size_t i = 0; i < bytes.size(); ++i) {
    ptr[i] = 0;
  }
}

}  // namespace

DemoResult run_demo() {
  DemoResult result{};
  result.native_version = tafrah_version();

  {
    std::vector<uint8_t> ek(tafrah_ml_kem_768_ek_size());
    std::vector<uint8_t> dk(tafrah_ml_kem_768_dk_size());
    std::vector<uint8_t> ct(tafrah_ml_kem_768_ct_size());
    std::vector<uint8_t> client_ss(tafrah_shared_secret_size());
    std::vector<uint8_t> server_ss(tafrah_shared_secret_size());

    check_status(
        tafrah_ml_kem_768_keygen(ek.data(), ek.size(), dk.data(), dk.size()),
        "tafrah_ml_kem_768_keygen");
    check_status(
        tafrah_ml_kem_768_encapsulate(
            ek.data(), ek.size(), ct.data(), ct.size(), client_ss.data(), client_ss.size()),
        "tafrah_ml_kem_768_encapsulate");
    check_status(
        tafrah_ml_kem_768_decapsulate(
            dk.data(), dk.size(), ct.data(), ct.size(), server_ss.data(), server_ss.size()),
        "tafrah_ml_kem_768_decapsulate");

    result.ml_kem_768_shared_secret_match = constant_time_equal(client_ss, server_ss);
    secure_zero(dk);
    secure_zero(client_ss);
    secure_zero(server_ss);
  }

  {
    std::vector<uint8_t> ek(tafrah_hqc_128_ek_size());
    std::vector<uint8_t> dk(tafrah_hqc_128_dk_size());
    std::vector<uint8_t> ct(tafrah_hqc_128_ct_size());
    std::vector<uint8_t> client_ss(tafrah_hqc_128_ss_size());
    std::vector<uint8_t> server_ss(tafrah_hqc_128_ss_size());

    check_status(tafrah_hqc_128_keygen(ek.data(), ek.size(), dk.data(), dk.size()), "tafrah_hqc_128_keygen");
    check_status(
        tafrah_hqc_128_encapsulate(
            ek.data(), ek.size(), ct.data(), ct.size(), client_ss.data(), client_ss.size()),
        "tafrah_hqc_128_encapsulate");
    check_status(
        tafrah_hqc_128_decapsulate(
            dk.data(), dk.size(), ct.data(), ct.size(), server_ss.data(), server_ss.size()),
        "tafrah_hqc_128_decapsulate");

    result.hqc_128_shared_secret_match = constant_time_equal(client_ss, server_ss);
    secure_zero(dk);
    secure_zero(client_ss);
    secure_zero(server_ss);
  }

  {
    const std::vector<uint8_t> msg = bytes_from_text("tafrah-auth-demo::ml-dsa-65");
    std::vector<uint8_t> tampered(msg);
    tampered.push_back(1);
    std::vector<uint8_t> vk(tafrah_ml_dsa_65_vk_size());
    std::vector<uint8_t> sk(tafrah_ml_dsa_65_sk_size());
    std::vector<uint8_t> sig(tafrah_ml_dsa_65_sig_size());

    check_status(tafrah_ml_dsa_65_keygen(vk.data(), vk.size(), sk.data(), sk.size()), "tafrah_ml_dsa_65_keygen");
    check_status(
        tafrah_ml_dsa_65_sign(sk.data(), sk.size(), msg.data(), msg.size(), sig.data(), sig.size()),
        "tafrah_ml_dsa_65_sign");

    result.ml_dsa_65_verify_ok = verify_result(
        tafrah_ml_dsa_65_verify(vk.data(), vk.size(), msg.data(), msg.size(), sig.data(), sig.size()),
        "tafrah_ml_dsa_65_verify");
    result.ml_dsa_65_tamper_rejected = !verify_result(
        tafrah_ml_dsa_65_verify(
            vk.data(), vk.size(), tampered.data(), tampered.size(), sig.data(), sig.size()),
        "tafrah_ml_dsa_65_verify_tampered");
    secure_zero(sk);
  }

  {
    const std::vector<uint8_t> msg = bytes_from_text("tafrah-auth-demo::slh-dsa-shake-128f");
    std::vector<uint8_t> tampered(msg);
    tampered.push_back(2);
    std::vector<uint8_t> vk(tafrah_slh_dsa_shake_128f_vk_size());
    std::vector<uint8_t> sk(tafrah_slh_dsa_shake_128f_sk_size());
    std::vector<uint8_t> sig(tafrah_slh_dsa_shake_128f_sig_size());

    check_status(
        tafrah_slh_dsa_shake_128f_keygen(vk.data(), vk.size(), sk.data(), sk.size()),
        "tafrah_slh_dsa_shake_128f_keygen");
    check_status(
        tafrah_slh_dsa_shake_128f_sign(
            sk.data(), sk.size(), msg.data(), msg.size(), sig.data(), sig.size()),
        "tafrah_slh_dsa_shake_128f_sign");

    result.slh_dsa_shake_128f_verify_ok = verify_result(
        tafrah_slh_dsa_shake_128f_verify(
            vk.data(), vk.size(), msg.data(), msg.size(), sig.data(), sig.size()),
        "tafrah_slh_dsa_shake_128f_verify");
    result.slh_dsa_shake_128f_tamper_rejected = !verify_result(
        tafrah_slh_dsa_shake_128f_verify(
            vk.data(), vk.size(), tampered.data(), tampered.size(), sig.data(), sig.size()),
        "tafrah_slh_dsa_shake_128f_verify_tampered");
    secure_zero(sk);
  }

  {
    const std::vector<uint8_t> msg = bytes_from_text("tafrah-auth-demo::falcon-512");
    std::vector<uint8_t> tampered(msg);
    tampered.push_back(3);
    std::vector<uint8_t> vk(tafrah_falcon_512_vk_size());
    std::vector<uint8_t> sk(tafrah_falcon_512_sk_size());
    std::vector<uint8_t> sig(tafrah_falcon_512_sig_size());
    size_t sig_written = 0;

    check_status(
        tafrah_falcon_512_keygen(vk.data(), vk.size(), sk.data(), sk.size()),
        "tafrah_falcon_512_keygen");
    check_status(
        tafrah_falcon_512_sign(
            sk.data(), sk.size(), msg.data(), msg.size(), sig.data(), sig.size(), &sig_written),
        "tafrah_falcon_512_sign");
    sig.resize(sig_written);

    result.falcon_512_verify_ok = verify_result(
        tafrah_falcon_512_verify(vk.data(), vk.size(), msg.data(), msg.size(), sig.data(), sig.size()),
        "tafrah_falcon_512_verify");
    result.falcon_512_tamper_rejected = !verify_result(
        tafrah_falcon_512_verify(
            vk.data(), vk.size(), tampered.data(), tampered.size(), sig.data(), sig.size()),
        "tafrah_falcon_512_verify_tampered");
    secure_zero(sk);
  }

  result.ok = result.ml_kem_768_shared_secret_match &&
              result.hqc_128_shared_secret_match &&
              result.ml_dsa_65_verify_ok &&
              result.ml_dsa_65_tamper_rejected &&
              result.slh_dsa_shake_128f_verify_ok &&
              result.slh_dsa_shake_128f_tamper_rejected &&
              result.falcon_512_verify_ok &&
              result.falcon_512_tamper_rejected;
  return result;
}

std::string result_to_json(const DemoResult& result, const std::string& language) {
  return std::string("{") +
         "\"language\":\"" + escape_json(language) + "\"," +
         "\"native_version\":\"" + escape_json(result.native_version) + "\"," +
         "\"ml_kem_768_shared_secret_match\":" + json_bool(result.ml_kem_768_shared_secret_match) + "," +
         "\"hqc_128_shared_secret_match\":" + json_bool(result.hqc_128_shared_secret_match) + "," +
         "\"ml_dsa_65_verify_ok\":" + json_bool(result.ml_dsa_65_verify_ok) + "," +
         "\"ml_dsa_65_tamper_rejected\":" + json_bool(result.ml_dsa_65_tamper_rejected) + "," +
         "\"slh_dsa_shake_128f_verify_ok\":" + json_bool(result.slh_dsa_shake_128f_verify_ok) + "," +
         "\"slh_dsa_shake_128f_tamper_rejected\":" + json_bool(result.slh_dsa_shake_128f_tamper_rejected) + "," +
         "\"falcon_512_verify_ok\":" + json_bool(result.falcon_512_verify_ok) + "," +
         "\"falcon_512_tamper_rejected\":" + json_bool(result.falcon_512_tamper_rejected) + "," +
         "\"overall_ok\":" + json_bool(result.ok) +
         "}";
}

}  // namespace tafrah_demo
