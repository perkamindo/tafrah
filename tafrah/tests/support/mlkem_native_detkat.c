#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fips202.h"

#define MLK_CONFIG_FILE "mlkem_native_test_config.h"
#include "kem.h"

void mlkem_native_test_randombytes(uint8_t *ptr, size_t len)
{
  memset(ptr, 0, len);
}

static void derive_seed(uint8_t *out,
                        size_t outlen,
                        const char *label,
                        unsigned count)
{
  uint8_t input[32];
  size_t label_len = strlen(label);
  size_t copy_len = label_len > sizeof(input) - 8 ? sizeof(input) - 8 : label_len;

  memset(input, 0, sizeof(input));
  memcpy(input, label, copy_len);
  input[24] = (uint8_t)MLK_CONFIG_PARAMETER_SET;
  input[25] = (uint8_t)(count & 0xFFu);
  input[26] = (uint8_t)((count >> 8) & 0xFFu);
  input[27] = (uint8_t)((count >> 16) & 0xFFu);
  input[28] = (uint8_t)((count >> 24) & 0xFFu);
  input[29] = 0xA5u;
  input[30] = 0x5Au;
  input[31] = (uint8_t)(copy_len * 17u);

  if (outlen == 32) {
    sha3_256(out, input, sizeof(input));
    return;
  }
  if (outlen == 64) {
    sha3_512(out, input, sizeof(input));
    return;
  }

  fprintf(stderr, "unsupported seed length: %zu\n", outlen);
  exit(1);
}

static void print_hex_field(const char *name, const uint8_t *bytes, size_t len)
{
  size_t i;
  printf("%s = ", name);
  for (i = 0; i < len; i++) {
    printf("%02X", bytes[i]);
  }
  printf("\n");
}

int main(void)
{
  unsigned count;
  uint8_t key_seed[64];
  uint8_t enc_seed[32];
  uint8_t pk[MLKEM_INDCCA_PUBLICKEYBYTES];
  uint8_t sk[MLKEM_INDCCA_SECRETKEYBYTES];
  uint8_t ct[MLKEM_INDCCA_CIPHERTEXTBYTES];
  uint8_t ss[MLKEM_SSBYTES];
  uint8_t ss_dec[MLKEM_SSBYTES];

  for (count = 0; count < 100; count++) {
    derive_seed(key_seed, sizeof(key_seed), "tafrah-mlkem-key", count);
    derive_seed(enc_seed, sizeof(enc_seed), "tafrah-mlkem-enc", count);

    if (crypto_kem_keypair_derand(pk, sk, key_seed) != 0) {
      fprintf(stderr, "keypair_derand failed for count=%u\n", count);
      return 1;
    }
    if (crypto_kem_enc_derand(ct, ss, pk, enc_seed) != 0) {
      fprintf(stderr, "enc_derand failed for count=%u\n", count);
      return 1;
    }
    if (crypto_kem_dec(ss_dec, ct, sk) != 0) {
      fprintf(stderr, "dec failed for count=%u\n", count);
      return 1;
    }
    if (memcmp(ss, ss_dec, MLKEM_SSBYTES) != 0) {
      fprintf(stderr, "shared secret mismatch for count=%u\n", count);
      return 1;
    }

    printf("count = %u\n", count);
    print_hex_field("key_seed", key_seed, sizeof(key_seed));
    print_hex_field("enc_seed", enc_seed, sizeof(enc_seed));
    print_hex_field("pk", pk, sizeof(pk));
    print_hex_field("sk", sk, sizeof(sk));
    print_hex_field("ct", ct, sizeof(ct));
    print_hex_field("ss", ss, sizeof(ss));
    printf("\n");
  }

  return 0;
}
