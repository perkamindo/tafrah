#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mldsa_native.h"

static void hex_print(const uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02X", buf[i]);
  }
  printf("\n");
}

static void fill_seed(unsigned count, uint8_t seed[MLDSA_SEEDBYTES]) {
  for (size_t i = 0; i < MLDSA_SEEDBYTES; i++) {
    seed[i] = (uint8_t)(MLD_CONFIG_PARAMETER_SET + 17U * count + i);
  }
}

static void fill_rnd(unsigned count, uint8_t rnd[MLDSA_RNDBYTES]) {
  for (size_t i = 0; i < MLDSA_RNDBYTES; i++) {
    rnd[i] = (uint8_t)(0xA0U + MLD_CONFIG_PARAMETER_SET + 11U * count + i);
  }
}

static size_t fill_ctx(unsigned count, uint8_t *ctx) {
  switch (count) {
  case 0:
    return 0;
  case 1: {
    static const uint8_t value[] = {
        'm', 'l', 'd', 's', 'a', '-', 'n', 'a', 't', 'i', 'v', 'e'};
    memcpy(ctx, value, sizeof(value));
    return sizeof(value);
  }
  default:
    for (size_t i = 0; i < 255; i++) {
      ctx[i] = (uint8_t)i;
    }
    return 255;
  }
}

static size_t fill_msg(unsigned count, uint8_t *msg) {
  switch (count) {
  case 0: {
    static const uint8_t value[] = "tafrah::mldsa-native::case0";
    memcpy(msg, value, sizeof(value) - 1);
    return sizeof(value) - 1;
  }
  case 1:
    for (size_t i = 0; i < 48; i++) {
      msg[i] = (uint8_t)(0xC0U + i);
    }
    return 48;
  default:
    for (size_t i = 0; i < 96; i++) {
      msg[i] = (uint8_t)(0x30U + i);
    }
    return 96;
  }
}

static void fill_mu(unsigned count, uint8_t mu[MLDSA_CRHBYTES]) {
  for (size_t i = 0; i < MLDSA_CRHBYTES; i++) {
    mu[i] = (uint8_t)(0x55U + count + i);
  }
}

static void fill_ph_sha2_256(unsigned count, uint8_t ph[32]) {
  for (size_t i = 0; i < 32; i++) {
    ph[i] = (uint8_t)(0x90U + 3U * count + i);
  }
}

static int emit_case(unsigned count) {
    uint8_t seed[MLDSA_SEEDBYTES];
    uint8_t rnd[MLDSA_RNDBYTES];
    uint8_t ctx[255];
    uint8_t msg[96];
    uint8_t mu[MLDSA_CRHBYTES];
    uint8_t ph_sha2_256[32];
    uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig_pure[CRYPTO_BYTES];
    uint8_t sig_extmu[CRYPTO_BYTES];
    uint8_t sig_prehash_sha2_256[CRYPTO_BYTES];
    uint8_t sig_prehash_shake256[CRYPTO_BYTES];
    size_t ctxlen;
    size_t msglen;
    size_t prelen;
    size_t siglen;

    fill_seed(count, seed);
    fill_rnd(count, rnd);
    ctxlen = fill_ctx(count, ctx);
    msglen = fill_msg(count, msg);
    fill_mu(count, mu);
    fill_ph_sha2_256(count, ph_sha2_256);

    if (mldsa_keypair_internal(pk, sk, seed) != 0) {
      return 1;
    }

    prelen = mldsa_prepare_domain_separation_prefix(pre, NULL, 0, ctx, ctxlen,
                                                    MLD_PREHASH_NONE);
    if (prelen == 0) {
      return 1;
    }
    if (mldsa_signature_internal(sig_pure, &siglen, msg, msglen, pre, prelen,
                                 rnd, sk, 0) != 0) {
      return 1;
    }
    if (siglen != CRYPTO_BYTES) {
      return 1;
    }

    if (mldsa_signature_internal(sig_extmu, &siglen, mu, MLDSA_CRHBYTES, NULL,
                                 0, rnd, sk, 1) != 0) {
      return 1;
    }
    if (siglen != CRYPTO_BYTES) {
      return 1;
    }

    if (mldsa_signature_pre_hash_internal(sig_prehash_sha2_256, &siglen,
                                          ph_sha2_256, sizeof(ph_sha2_256), ctx,
                                          ctxlen, rnd, sk,
                                          MLD_PREHASH_SHA2_256) != 0) {
      return 1;
    }
    if (siglen != CRYPTO_BYTES) {
      return 1;
    }

    if (mldsa_signature_pre_hash_shake256(sig_prehash_shake256, &siglen, msg,
                                          msglen, ctx, ctxlen, rnd, sk) != 0) {
      return 1;
    }
    if (siglen != CRYPTO_BYTES) {
      return 1;
    }

    if (mldsa_verify(sig_pure, CRYPTO_BYTES, msg, msglen, ctx, ctxlen, pk) !=
        0) {
      return 1;
    }
    if (mldsa_verify_extmu(sig_extmu, CRYPTO_BYTES, mu, pk) != 0) {
      return 1;
    }
    if (mldsa_verify_pre_hash_internal(sig_prehash_sha2_256, CRYPTO_BYTES,
                                       ph_sha2_256, sizeof(ph_sha2_256), ctx,
                                       ctxlen, pk, MLD_PREHASH_SHA2_256) != 0) {
      return 1;
    }
    if (mldsa_verify_pre_hash_shake256(sig_prehash_shake256, CRYPTO_BYTES, msg,
                                       msglen, ctx, ctxlen, pk) != 0) {
      return 1;
    }

    printf("count = %u\n", count);
    printf("seed = ");
    hex_print(seed, sizeof(seed));
    printf("rnd = ");
    hex_print(rnd, sizeof(rnd));
    printf("ctx = ");
    hex_print(ctx, ctxlen);
    printf("msg = ");
    hex_print(msg, msglen);
    printf("mu = ");
    hex_print(mu, sizeof(mu));
    printf("ph_sha2_256 = ");
    hex_print(ph_sha2_256, sizeof(ph_sha2_256));
    printf("pk = ");
    hex_print(pk, sizeof(pk));
    printf("sk = ");
    hex_print(sk, sizeof(sk));
    printf("sig_pure = ");
    hex_print(sig_pure, sizeof(sig_pure));
    printf("sig_extmu = ");
    hex_print(sig_extmu, sizeof(sig_extmu));
    printf("sig_prehash_sha2_256 = ");
    hex_print(sig_prehash_sha2_256, sizeof(sig_prehash_sha2_256));
    printf("sig_prehash_shake256 = ");
    hex_print(sig_prehash_shake256, sizeof(sig_prehash_shake256));
    printf("\n");

    return 0;
}

int main(int argc, char **argv) {
  if (argc == 1) {
    static const unsigned default_counts[] = {0, 1, 2};
    for (size_t i = 0; i < sizeof(default_counts) / sizeof(default_counts[0]); i++) {
      if (emit_case(default_counts[i]) != 0) {
        return 1;
      }
    }
    return 0;
  }

  for (int i = 1; i < argc; i++) {
    char *endptr = NULL;
    unsigned long value = strtoul(argv[i], &endptr, 10);
    if (endptr == argv[i] || *endptr != '\0' || value > 99UL) {
      fprintf(stderr, "invalid count: %s\n", argv[i]);
      return 1;
    }
    if (emit_case((unsigned)value) != 0) {
      return 1;
    }
  }

  return 0;
}
