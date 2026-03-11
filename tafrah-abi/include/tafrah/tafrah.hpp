#ifndef TAFRAH_INSTALL_HEADER_HPP
#define TAFRAH_INSTALL_HEADER_HPP

#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <tafrah/tafrah.h>

namespace tafrah {

inline void check_status(int status, const char* op) {
  if (status != TAFRAH_STATUS_OK) {
    throw std::runtime_error(std::string(op) + ": " + tafrah_status_string(status));
  }
}

inline bool verify_status(int status, const char* op) {
  if (status == TAFRAH_STATUS_OK) {
    return true;
  }
  if (status == TAFRAH_STATUS_VERIFICATION_FAILED) {
    return false;
  }
  throw std::runtime_error(std::string(op) + ": " + tafrah_status_string(status));
}

struct KemKeypair {
  std::vector<uint8_t> public_key;
  std::vector<uint8_t> secret_key;
};

struct SignatureKeypair {
  std::vector<uint8_t> public_key;
  std::vector<uint8_t> secret_key;
};

inline std::string version() { return tafrah_version(); }

inline KemKeypair ml_kem_768_keygen() {
  KemKeypair out{
      std::vector<uint8_t>(tafrah_ml_kem_768_ek_size()),
      std::vector<uint8_t>(tafrah_ml_kem_768_dk_size()),
  };
  check_status(
      tafrah_ml_kem_768_keygen(
          out.public_key.data(), out.public_key.size(), out.secret_key.data(), out.secret_key.size()),
      "tafrah_ml_kem_768_keygen");
  return out;
}

inline std::pair<std::vector<uint8_t>, std::vector<uint8_t>> ml_kem_768_encapsulate(
    const std::vector<uint8_t>& public_key) {
  std::vector<uint8_t> ciphertext(tafrah_ml_kem_768_ct_size());
  std::vector<uint8_t> shared_secret(tafrah_shared_secret_size());
  check_status(
      tafrah_ml_kem_768_encapsulate(
          public_key.data(),
          public_key.size(),
          ciphertext.data(),
          ciphertext.size(),
          shared_secret.data(),
          shared_secret.size()),
      "tafrah_ml_kem_768_encapsulate");
  return {ciphertext, shared_secret};
}

inline std::vector<uint8_t> ml_kem_768_decapsulate(
    const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& ciphertext) {
  std::vector<uint8_t> shared_secret(tafrah_shared_secret_size());
  check_status(
      tafrah_ml_kem_768_decapsulate(
          secret_key.data(),
          secret_key.size(),
          ciphertext.data(),
          ciphertext.size(),
          shared_secret.data(),
          shared_secret.size()),
      "tafrah_ml_kem_768_decapsulate");
  return shared_secret;
}

inline SignatureKeypair ml_dsa_65_keygen() {
  SignatureKeypair out{
      std::vector<uint8_t>(tafrah_ml_dsa_65_vk_size()),
      std::vector<uint8_t>(tafrah_ml_dsa_65_sk_size()),
  };
  check_status(
      tafrah_ml_dsa_65_keygen(
          out.public_key.data(), out.public_key.size(), out.secret_key.data(), out.secret_key.size()),
      "tafrah_ml_dsa_65_keygen");
  return out;
}

inline std::vector<uint8_t> ml_dsa_65_sign(
    const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& message) {
  std::vector<uint8_t> signature(tafrah_ml_dsa_65_sig_size());
  check_status(
      tafrah_ml_dsa_65_sign(
          secret_key.data(),
          secret_key.size(),
          message.data(),
          message.size(),
          signature.data(),
          signature.size()),
      "tafrah_ml_dsa_65_sign");
  return signature;
}

inline bool ml_dsa_65_verify(
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature) {
  return verify_status(
      tafrah_ml_dsa_65_verify(
          public_key.data(),
          public_key.size(),
          message.data(),
          message.size(),
          signature.data(),
          signature.size()),
      "tafrah_ml_dsa_65_verify");
}

inline SignatureKeypair slh_dsa_shake_128f_keygen() {
  SignatureKeypair out{
      std::vector<uint8_t>(tafrah_slh_dsa_shake_128f_vk_size()),
      std::vector<uint8_t>(tafrah_slh_dsa_shake_128f_sk_size()),
  };
  check_status(
      tafrah_slh_dsa_shake_128f_keygen(
          out.public_key.data(), out.public_key.size(), out.secret_key.data(), out.secret_key.size()),
      "tafrah_slh_dsa_shake_128f_keygen");
  return out;
}

inline std::vector<uint8_t> slh_dsa_shake_128f_sign(
    const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& message) {
  std::vector<uint8_t> signature(tafrah_slh_dsa_shake_128f_sig_size());
  check_status(
      tafrah_slh_dsa_shake_128f_sign(
          secret_key.data(),
          secret_key.size(),
          message.data(),
          message.size(),
          signature.data(),
          signature.size()),
      "tafrah_slh_dsa_shake_128f_sign");
  return signature;
}

inline bool slh_dsa_shake_128f_verify(
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature) {
  return verify_status(
      tafrah_slh_dsa_shake_128f_verify(
          public_key.data(),
          public_key.size(),
          message.data(),
          message.size(),
          signature.data(),
          signature.size()),
      "tafrah_slh_dsa_shake_128f_verify");
}

inline SignatureKeypair falcon_512_keygen() {
  SignatureKeypair out{
      std::vector<uint8_t>(tafrah_falcon_512_vk_size()),
      std::vector<uint8_t>(tafrah_falcon_512_sk_size()),
  };
  check_status(
      tafrah_falcon_512_keygen(
          out.public_key.data(), out.public_key.size(), out.secret_key.data(), out.secret_key.size()),
      "tafrah_falcon_512_keygen");
  return out;
}

inline std::vector<uint8_t> falcon_512_sign(
    const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& message) {
  std::vector<uint8_t> signature(tafrah_falcon_512_sig_size());
  size_t written = 0;
  check_status(
      tafrah_falcon_512_sign(
          secret_key.data(),
          secret_key.size(),
          message.data(),
          message.size(),
          signature.data(),
          signature.size(),
          &written),
      "tafrah_falcon_512_sign");
  signature.resize(written);
  return signature;
}

inline bool falcon_512_verify(
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature) {
  return verify_status(
      tafrah_falcon_512_verify(
          public_key.data(),
          public_key.size(),
          message.data(),
          message.size(),
          signature.data(),
          signature.size()),
      "tafrah_falcon_512_verify");
}

inline KemKeypair hqc_128_keygen() {
  KemKeypair out{
      std::vector<uint8_t>(tafrah_hqc_128_ek_size()),
      std::vector<uint8_t>(tafrah_hqc_128_dk_size()),
  };
  check_status(
      tafrah_hqc_128_keygen(
          out.public_key.data(), out.public_key.size(), out.secret_key.data(), out.secret_key.size()),
      "tafrah_hqc_128_keygen");
  return out;
}

inline std::pair<std::vector<uint8_t>, std::vector<uint8_t>> hqc_128_encapsulate(
    const std::vector<uint8_t>& public_key) {
  std::vector<uint8_t> ciphertext(tafrah_hqc_128_ct_size());
  std::vector<uint8_t> shared_secret(tafrah_hqc_128_ss_size());
  check_status(
      tafrah_hqc_128_encapsulate(
          public_key.data(),
          public_key.size(),
          ciphertext.data(),
          ciphertext.size(),
          shared_secret.data(),
          shared_secret.size()),
      "tafrah_hqc_128_encapsulate");
  return {ciphertext, shared_secret};
}

inline std::vector<uint8_t> hqc_128_decapsulate(
    const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& ciphertext) {
  std::vector<uint8_t> shared_secret(tafrah_hqc_128_ss_size());
  check_status(
      tafrah_hqc_128_decapsulate(
          secret_key.data(),
          secret_key.size(),
          ciphertext.data(),
          ciphertext.size(),
          shared_secret.data(),
          shared_secret.size()),
      "tafrah_hqc_128_decapsulate");
  return shared_secret;
}

}  // namespace tafrah

#endif
