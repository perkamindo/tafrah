#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "slh_dsa.h"
#include "slh_prehash.h"

static const slh_param_t *lookup_params(const char *alg_id) {
  struct entry {
    const char *alg_id;
    const slh_param_t *params;
  };
  static const struct entry entries[] = {
      {"SLH-DSA-SHA2-128s", &slh_dsa_sha2_128s},
      {"SLH-DSA-SHA2-128f", &slh_dsa_sha2_128f},
      {"SLH-DSA-SHA2-192s", &slh_dsa_sha2_192s},
      {"SLH-DSA-SHA2-192f", &slh_dsa_sha2_192f},
      {"SLH-DSA-SHA2-256s", &slh_dsa_sha2_256s},
      {"SLH-DSA-SHA2-256f", &slh_dsa_sha2_256f},
      {"SLH-DSA-SHAKE-128s", &slh_dsa_shake_128s},
      {"SLH-DSA-SHAKE-128f", &slh_dsa_shake_128f},
      {"SLH-DSA-SHAKE-192s", &slh_dsa_shake_192s},
      {"SLH-DSA-SHAKE-192f", &slh_dsa_shake_192f},
      {"SLH-DSA-SHAKE-256s", &slh_dsa_shake_256s},
      {"SLH-DSA-SHAKE-256f", &slh_dsa_shake_256f},
  };
  size_t i;

  for (i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
    if (strcmp(entries[i].alg_id, alg_id) == 0) {
      return entries[i].params;
    }
  }
  return NULL;
}

static int hex_value(int c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

static size_t hex_decode(const char *hex, uint8_t *out, size_t cap) {
  size_t len;
  size_t i;

  if (strcmp(hex, "-") == 0) {
    return 0;
  }

  len = strlen(hex);
  if ((len & 1) != 0 || (len / 2) > cap) {
    return SIZE_MAX;
  }

  for (i = 0; i < len / 2; i++) {
    int hi = hex_value(hex[2 * i]);
    int lo = hex_value(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      return SIZE_MAX;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return len / 2;
}

static void print_hex(const uint8_t *bytes, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    printf("%02X", bytes[i]);
  }
  printf("\n");
}

int main(int argc, char **argv) {
  const slh_param_t *params;
  const char *mode;
  const char *ph;
  size_t pk_sz;
  size_t sk_sz;
  size_t sig_sz;
  size_t n;
  uint8_t *seed_material;
  uint8_t *msg;
  uint8_t *ctx;
  uint8_t *addrnd_buf;
  uint8_t *pk;
  uint8_t *sk;
  uint8_t *sig;
  const uint8_t *addrnd = NULL;
  size_t seed_len;
  size_t msg_len;
  size_t ctx_len;
  size_t addrnd_len;
  size_t written;
  int ok = 0;

  if (argc != 8) {
    fprintf(stderr, "usage: %s ALG_ID MODE SEED_HEX MSG_HEX CTX_HEX ADDRND_HEX PH\n", argv[0]);
    return 1;
  }

  params = lookup_params(argv[1]);
  if (params == NULL) {
    fprintf(stderr, "unknown algorithm id: %s\n", argv[1]);
    return 1;
  }
  mode = argv[2];
  ph = argv[7];
  pk_sz = slh_pk_sz(params);
  sk_sz = slh_sk_sz(params);
  sig_sz = slh_sig_sz(params);
  n = pk_sz / 2;

  seed_material = (uint8_t *)malloc(3 * n);
  msg = (uint8_t *)malloc(strlen(argv[4]) / 2 + 1);
  ctx = (uint8_t *)malloc(strlen(argv[5]) / 2 + 1);
  addrnd_buf = (uint8_t *)malloc(n);
  pk = (uint8_t *)malloc(pk_sz);
  sk = (uint8_t *)malloc(sk_sz);
  sig = (uint8_t *)malloc(sig_sz);
  if (seed_material == NULL || msg == NULL || ctx == NULL || addrnd_buf == NULL || pk == NULL ||
      sk == NULL || sig == NULL) {
    fprintf(stderr, "allocation failure\n");
    return 1;
  }

  seed_len = hex_decode(argv[3], seed_material, 3 * n);
  msg_len = hex_decode(argv[4], msg, strlen(argv[4]) / 2 + 1);
  ctx_len = hex_decode(argv[5], ctx, strlen(argv[5]) / 2 + 1);
  if (seed_len != 3 * n || msg_len == SIZE_MAX || ctx_len == SIZE_MAX) {
    fprintf(stderr, "hex decode failure\n");
    return 1;
  }

  if (strcmp(argv[6], "-") != 0) {
    addrnd_len = hex_decode(argv[6], addrnd_buf, n);
    if (addrnd_len != n) {
      fprintf(stderr, "invalid addrnd length\n");
      return 1;
    }
    addrnd = addrnd_buf;
  }

  if (slh_keygen_internal(sk, pk, seed_material, seed_material + n, seed_material + 2 * n,
                          params) != 0) {
    fprintf(stderr, "slh_keygen_internal failed\n");
    return 1;
  }

  if (strcmp(mode, "internal") == 0) {
    written = slh_sign_internal(sig, msg, msg_len, sk, addrnd, params);
    ok = slh_verify_internal(msg, msg_len, sig, written, pk, params);
  } else if (strcmp(mode, "pure") == 0) {
    written = slh_sign(sig, msg, msg_len, ctx, ctx_len, sk, addrnd, params);
    ok = slh_verify(msg, msg_len, sig, written, ctx, ctx_len, pk, params);
  } else if (strcmp(mode, "prehash") == 0) {
    written = hash_slh_sign(sig, msg, msg_len, ctx, ctx_len, ph, sk, addrnd, params);
    ok = hash_slh_verify(msg, msg_len, sig, written, ctx, ctx_len, ph, pk, params);
  } else {
    fprintf(stderr, "unknown mode: %s\n", mode);
    return 1;
  }

  if (written != sig_sz || !ok) {
    fprintf(stderr, "oracle sign/verify failure\n");
    return 1;
  }

  print_hex(pk, pk_sz);
  print_hex(sk, sk_sz);
  print_hex(sig, sig_sz);
  return 0;
}
