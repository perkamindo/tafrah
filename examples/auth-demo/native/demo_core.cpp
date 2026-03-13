#include "demo_core.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <initializer_list>
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

bool expect_status(int status, int expected, const char* op) {
  if (status == expected) {
    return true;
  }
  throw std::runtime_error(
      std::string(op) + ": expected " + tafrah_status_string(expected) + ", got " +
      tafrah_status_string(status));
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

std::vector<uint8_t> concat(
    const std::vector<uint8_t>& lhs, const std::vector<uint8_t>& rhs) {
  std::vector<uint8_t> out;
  out.reserve(lhs.size() + rhs.size());
  out.insert(out.end(), lhs.begin(), lhs.end());
  out.insert(out.end(), rhs.begin(), rhs.end());
  return out;
}

void append_u32_be(std::vector<uint8_t>& out, uint32_t value) {
  out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(value & 0xFF));
}

std::vector<uint8_t> encode_parts(std::initializer_list<std::vector<uint8_t>> parts) {
  std::vector<uint8_t> out;
  for (const auto& part : parts) {
    append_u32_be(out, static_cast<uint32_t>(part.size()));
    out.insert(out.end(), part.begin(), part.end());
  }
  return out;
}

uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& data) {
  static constexpr uint32_t k[64] = {
      0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
      0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
      0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
      0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
      0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
      0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
      0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
      0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
      0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
      0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
      0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
      0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
      0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
  };

  uint32_t h0 = 0x6a09e667u;
  uint32_t h1 = 0xbb67ae85u;
  uint32_t h2 = 0x3c6ef372u;
  uint32_t h3 = 0xa54ff53au;
  uint32_t h4 = 0x510e527fu;
  uint32_t h5 = 0x9b05688cu;
  uint32_t h6 = 0x1f83d9abu;
  uint32_t h7 = 0x5be0cd19u;

  std::vector<uint8_t> padded(data);
  padded.push_back(0x80);
  while ((padded.size() % 64) != 56) {
    padded.push_back(0x00);
  }

  const uint64_t bit_len = static_cast<uint64_t>(data.size()) * 8u;
  for (int shift = 56; shift >= 0; shift -= 8) {
    padded.push_back(static_cast<uint8_t>((bit_len >> shift) & 0xFF));
  }

  for (size_t chunk = 0; chunk < padded.size(); chunk += 64) {
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i) {
      const size_t base = chunk + (i * 4);
      w[i] = (static_cast<uint32_t>(padded[base]) << 24) |
             (static_cast<uint32_t>(padded[base + 1]) << 16) |
             (static_cast<uint32_t>(padded[base + 2]) << 8) |
             static_cast<uint32_t>(padded[base + 3]);
    }
    for (size_t i = 16; i < 64; ++i) {
      const uint32_t s0 =
          rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const uint32_t s1 =
          rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h0;
    uint32_t b = h1;
    uint32_t c = h2;
    uint32_t d = h3;
    uint32_t e = h4;
    uint32_t f = h5;
    uint32_t g = h6;
    uint32_t h = h7;

    for (size_t i = 0; i < 64; ++i) {
      const uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const uint32_t ch = (e & f) ^ ((~e) & g);
      const uint32_t temp1 = h + s1 + ch + k[i] + w[i];
      const uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temp2 = s0 + maj;

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
    h5 += f;
    h6 += g;
    h7 += h;
  }

  std::array<uint8_t, 32> out{};
  const uint32_t words[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
  for (size_t i = 0; i < 8; ++i) {
    out[(i * 4) + 0] = static_cast<uint8_t>((words[i] >> 24) & 0xFF);
    out[(i * 4) + 1] = static_cast<uint8_t>((words[i] >> 16) & 0xFF);
    out[(i * 4) + 2] = static_cast<uint8_t>((words[i] >> 8) & 0xFF);
    out[(i * 4) + 3] = static_cast<uint8_t>(words[i] & 0xFF);
  }
  return out;
}

std::vector<uint8_t> sha256_vec(const std::vector<uint8_t>& data) {
  const auto digest = sha256(data);
  return std::vector<uint8_t>(digest.begin(), digest.end());
}

std::vector<uint8_t> hmac_sha256(
    const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
  static constexpr size_t block_size = 64;
  std::vector<uint8_t> key_block(block_size, 0);
  if (key.size() > block_size) {
    const auto hashed = sha256_vec(key);
    std::copy(hashed.begin(), hashed.end(), key_block.begin());
  } else {
    std::copy(key.begin(), key.end(), key_block.begin());
  }

  std::vector<uint8_t> o_key_pad(block_size, 0x5c);
  std::vector<uint8_t> i_key_pad(block_size, 0x36);
  for (size_t i = 0; i < block_size; ++i) {
    o_key_pad[i] ^= key_block[i];
    i_key_pad[i] ^= key_block[i];
  }

  auto inner = i_key_pad;
  inner.insert(inner.end(), data.begin(), data.end());
  const auto inner_hash = sha256_vec(inner);

  auto outer = o_key_pad;
  outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
  return sha256_vec(outer);
}

std::vector<uint8_t> hkdf_sha256(
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& info,
    size_t length) {
  const auto prk = hmac_sha256(salt, ikm);
  std::vector<uint8_t> okm;
  okm.reserve(length);
  std::vector<uint8_t> block;
  uint8_t counter = 1;
  while (okm.size() < length) {
    std::vector<uint8_t> data(block);
    data.insert(data.end(), info.begin(), info.end());
    data.push_back(counter);
    block = hmac_sha256(prk, data);
    const size_t take = std::min(block.size(), length - okm.size());
    okm.insert(okm.end(), block.begin(), block.begin() + static_cast<ptrdiff_t>(take));
    ++counter;
  }
  return okm;
}

struct SymmetricKeys {
  std::vector<uint8_t> enc;
  std::vector<uint8_t> mac;
};

SymmetricKeys derive_transport_keys(const std::vector<uint8_t>& shared_secret) {
  const auto material = hkdf_sha256(
      shared_secret,
      bytes_from_text("tafrah-auth-demo::transport-salt"),
      encode_parts({bytes_from_text("tafrah-auth-demo::transport")}),
      64);
  return SymmetricKeys{
      std::vector<uint8_t>(material.begin(), material.begin() + 32),
      std::vector<uint8_t>(material.begin() + 32, material.begin() + 64),
  };
}

std::vector<uint8_t> derive_nonce(const std::vector<uint8_t>& shared_secret) {
  const auto seed = sha256_vec(concat(shared_secret, bytes_from_text("tafrah-auth-demo::nonce")));
  return std::vector<uint8_t>(seed.begin(), seed.begin() + 16);
}

std::vector<uint8_t> stream_xor(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& label,
    const std::vector<uint8_t>& data) {
  const auto stream = hkdf_sha256(
      key,
      bytes_from_text("tafrah-auth-demo::stream-salt"),
      encode_parts({bytes_from_text("tafrah-auth-demo::stream"), label, nonce}),
      data.size());
  std::vector<uint8_t> out(data.size(), 0);
  for (size_t i = 0; i < data.size(); ++i) {
    out[i] = data[i] ^ stream[i];
  }
  return out;
}

std::string to_hex(const std::vector<uint8_t>& bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t byte : bytes) {
    out.push_back(kHex[(byte >> 4) & 0x0F]);
    out.push_back(kHex[byte & 0x0F]);
  }
  return out;
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
    const auto transport = derive_transport_keys(client_ss);
    const auto nonce = derive_nonce(client_ss);
    const auto plaintext = bytes_from_text("tafrah-auth-demo::symmetric-roundtrip");
    const auto ciphertext =
        stream_xor(transport.enc, nonce, bytes_from_text("client->server"), plaintext);
    const auto recovered =
        stream_xor(transport.enc, nonce, bytes_from_text("client->server"), ciphertext);
    result.symmetric_roundtrip_ok = constant_time_equal(plaintext, recovered);
    const auto hash_input = bytes_from_text("tafrah-auth-demo::hash::sha256");
    result.hash_sha256_ok =
        to_hex(sha256_vec(hash_input)) ==
        "5f36ca6b07d4d4a0162b71332eddefb1b79719d4719e09e2e880c059881ef00b";
    std::vector<uint8_t> truncated_ct(ct.begin(), ct.end() - 1);
    result.ml_kem_768_truncated_ct_rejected = expect_status(
        tafrah_ml_kem_768_decapsulate(
            dk.data(),
            dk.size(),
            truncated_ct.data(),
            truncated_ct.size(),
            server_ss.data(),
            server_ss.size()),
        TAFRAH_STATUS_INVALID_LENGTH,
        "tafrah_ml_kem_768_decapsulate_truncated");
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
    std::vector<uint8_t> truncated_ct(ct.begin(), ct.end() - 1);
    result.hqc_128_truncated_ct_rejected = expect_status(
        tafrah_hqc_128_decapsulate(
            dk.data(),
            dk.size(),
            truncated_ct.data(),
            truncated_ct.size(),
            server_ss.data(),
            server_ss.size()),
        TAFRAH_STATUS_INVALID_LENGTH,
        "tafrah_hqc_128_decapsulate_truncated");
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
    std::vector<uint8_t> truncated_sig(sig.begin(), sig.end() - 1);
    result.ml_dsa_65_truncated_sig_rejected = expect_status(
        tafrah_ml_dsa_65_verify(
            vk.data(),
            vk.size(),
            msg.data(),
            msg.size(),
            truncated_sig.data(),
            truncated_sig.size()),
        TAFRAH_STATUS_INVALID_LENGTH,
        "tafrah_ml_dsa_65_verify_truncated_sig");
    secure_zero(sk);
  }

  {
    const std::vector<uint8_t> msg = bytes_from_text("tafrah-auth-demo::slh-dsa-shake-128f");
    std::vector<uint8_t> tampered(msg);
    tampered.push_back(2);
    std::vector<uint8_t> prehash_tampered(msg);
    prehash_tampered.push_back(4);
    std::vector<uint8_t> vk(tafrah_slh_dsa_shake_128f_vk_size());
    std::vector<uint8_t> sk(tafrah_slh_dsa_shake_128f_sk_size());
    std::vector<uint8_t> sig(tafrah_slh_dsa_shake_128f_sig_size());
    std::vector<uint8_t> prehash_sig(tafrah_slh_dsa_shake_128f_sig_size());

    check_status(
        tafrah_slh_dsa_shake_128f_keygen(vk.data(), vk.size(), sk.data(), sk.size()),
        "tafrah_slh_dsa_shake_128f_keygen");
    check_status(
        tafrah_slh_dsa_shake_128f_sign(
            sk.data(), sk.size(), msg.data(), msg.size(), sig.data(), sig.size()),
        "tafrah_slh_dsa_shake_128f_sign");
    check_status(
        tafrah_slh_dsa_shake_128f_hash_sha2_256_sign(
            sk.data(), sk.size(), msg.data(), msg.size(), prehash_sig.data(), prehash_sig.size()),
        "tafrah_slh_dsa_shake_128f_hash_sha2_256_sign");

    result.slh_dsa_shake_128f_verify_ok = verify_result(
        tafrah_slh_dsa_shake_128f_verify(
            vk.data(), vk.size(), msg.data(), msg.size(), sig.data(), sig.size()),
        "tafrah_slh_dsa_shake_128f_verify");
    result.slh_dsa_shake_128f_prehash_verify_ok = verify_result(
        tafrah_slh_dsa_shake_128f_hash_sha2_256_verify(
            vk.data(), vk.size(), msg.data(), msg.size(), prehash_sig.data(), prehash_sig.size()),
        "tafrah_slh_dsa_shake_128f_hash_sha2_256_verify");
    result.slh_dsa_shake_128f_tamper_rejected = !verify_result(
        tafrah_slh_dsa_shake_128f_verify(
            vk.data(), vk.size(), tampered.data(), tampered.size(), sig.data(), sig.size()),
        "tafrah_slh_dsa_shake_128f_verify_tampered");
    result.slh_dsa_shake_128f_prehash_tamper_rejected = !verify_result(
        tafrah_slh_dsa_shake_128f_hash_sha2_256_verify(
            vk.data(),
            vk.size(),
            prehash_tampered.data(),
            prehash_tampered.size(),
            prehash_sig.data(),
            prehash_sig.size()),
        "tafrah_slh_dsa_shake_128f_hash_sha2_256_verify_tampered");
    std::vector<uint8_t> truncated_sig(sig.begin(), sig.end() - 1);
    result.slh_dsa_shake_128f_truncated_sig_rejected = expect_status(
        tafrah_slh_dsa_shake_128f_verify(
            vk.data(),
            vk.size(),
            msg.data(),
            msg.size(),
            truncated_sig.data(),
            truncated_sig.size()),
        TAFRAH_STATUS_INVALID_LENGTH,
        "tafrah_slh_dsa_shake_128f_verify_truncated_sig");
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
    std::vector<uint8_t> truncated_sig(sig.begin(), sig.end() - 1);
    result.falcon_512_truncated_sig_rejected = expect_status(
        tafrah_falcon_512_verify(
            vk.data(),
            vk.size(),
            msg.data(),
            msg.size(),
            truncated_sig.data(),
            truncated_sig.size()),
        TAFRAH_STATUS_INVALID_LENGTH,
        "tafrah_falcon_512_verify_truncated_sig");
    secure_zero(sk);
  }

  result.ok = result.ml_kem_768_shared_secret_match &&
              result.ml_kem_768_truncated_ct_rejected &&
              result.symmetric_roundtrip_ok &&
              result.hash_sha256_ok &&
              result.hqc_128_shared_secret_match &&
              result.hqc_128_truncated_ct_rejected &&
              result.ml_dsa_65_verify_ok &&
              result.ml_dsa_65_tamper_rejected &&
              result.ml_dsa_65_truncated_sig_rejected &&
              result.slh_dsa_shake_128f_verify_ok &&
              result.slh_dsa_shake_128f_prehash_verify_ok &&
              result.slh_dsa_shake_128f_prehash_tamper_rejected &&
              result.slh_dsa_shake_128f_tamper_rejected &&
              result.slh_dsa_shake_128f_truncated_sig_rejected &&
              result.falcon_512_verify_ok &&
              result.falcon_512_tamper_rejected &&
              result.falcon_512_truncated_sig_rejected;
  return result;
}

std::string result_to_json(const DemoResult& result, const std::string& language) {
  return std::string("{") +
         "\"language\":\"" + escape_json(language) + "\"," +
         "\"native_version\":\"" + escape_json(result.native_version) + "\"," +
         "\"ml_kem_768_shared_secret_match\":" + json_bool(result.ml_kem_768_shared_secret_match) + "," +
         "\"ml_kem_768_truncated_ct_rejected\":" + json_bool(result.ml_kem_768_truncated_ct_rejected) + "," +
         "\"symmetric_roundtrip_ok\":" + json_bool(result.symmetric_roundtrip_ok) + "," +
         "\"hash_sha256_ok\":" + json_bool(result.hash_sha256_ok) + "," +
         "\"hqc_128_shared_secret_match\":" + json_bool(result.hqc_128_shared_secret_match) + "," +
         "\"hqc_128_truncated_ct_rejected\":" + json_bool(result.hqc_128_truncated_ct_rejected) + "," +
         "\"ml_dsa_65_verify_ok\":" + json_bool(result.ml_dsa_65_verify_ok) + "," +
         "\"ml_dsa_65_tamper_rejected\":" + json_bool(result.ml_dsa_65_tamper_rejected) + "," +
         "\"ml_dsa_65_truncated_sig_rejected\":" + json_bool(result.ml_dsa_65_truncated_sig_rejected) + "," +
         "\"slh_dsa_shake_128f_verify_ok\":" + json_bool(result.slh_dsa_shake_128f_verify_ok) + "," +
         "\"slh_dsa_shake_128f_prehash_verify_ok\":" +
             json_bool(result.slh_dsa_shake_128f_prehash_verify_ok) + "," +
         "\"slh_dsa_shake_128f_prehash_tamper_rejected\":" +
             json_bool(result.slh_dsa_shake_128f_prehash_tamper_rejected) + "," +
         "\"slh_dsa_shake_128f_tamper_rejected\":" + json_bool(result.slh_dsa_shake_128f_tamper_rejected) + "," +
         "\"slh_dsa_shake_128f_truncated_sig_rejected\":" +
             json_bool(result.slh_dsa_shake_128f_truncated_sig_rejected) + "," +
         "\"falcon_512_verify_ok\":" + json_bool(result.falcon_512_verify_ok) + "," +
         "\"falcon_512_tamper_rejected\":" + json_bool(result.falcon_512_tamper_rejected) + "," +
         "\"falcon_512_truncated_sig_rejected\":" + json_bool(result.falcon_512_truncated_sig_rejected) + "," +
         "\"overall_ok\":" + json_bool(result.ok) +
         "}";
}

}  // namespace tafrah_demo
