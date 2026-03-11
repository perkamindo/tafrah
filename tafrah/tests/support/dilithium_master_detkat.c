#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fips202.h"
#include "randombytes.h"
#include "sign.h"

#define NVECTORS 16
#define MAX_MLEN (33 * NVECTORS)

/* Initial SHAKE128 state after absorbing the empty string. */
static keccak_state rngstate = {
    {0x1F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     (1ULL << 63), 0, 0, 0, 0},
    SHAKE128_RATE
};

void randombytes(uint8_t *x, size_t xlen) {
  shake128_squeeze(x, xlen, &rngstate);
}

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
  size_t i;

  printf("%s", label);
  for(i = 0; i < len; ++i) {
    printf("%02X", buf[i]);
  }
  if(len == 0) {
    printf("00");
  }
  printf("\n");
}

int main(void) {
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t msg[MAX_MLEN];
  uint8_t sm[CRYPTO_BYTES + MAX_MLEN];
  uint8_t opened[CRYPTO_BYTES + MAX_MLEN];
  size_t opened_len;
  size_t smlen;
  unsigned int count;

  for(count = 0; count < NVECTORS; ++count) {
    size_t mlen = 33 * (count + 1);

    randombytes(msg, mlen);
    crypto_sign_keypair(pk, sk);

    if(crypto_sign(sm, &smlen, msg, mlen, NULL, 0, sk) != 0) {
      return 1;
    }

    if(crypto_sign_open(opened, &opened_len, sm, smlen, NULL, 0, pk) != 0) {
      return 2;
    }

    if(opened_len != mlen || memcmp(opened, msg, mlen) != 0) {
      return 3;
    }

    printf("count = %u\n", count);
    printf("mlen = %zu\n", mlen);
    print_hex("msg = ", msg, mlen);
    print_hex("pk = ", pk, CRYPTO_PUBLICKEYBYTES);
    printf("smlen = %zu\n", smlen);
    print_hex("sm = ", sm, smlen);
    printf("\n");
  }

  return 0;
}
