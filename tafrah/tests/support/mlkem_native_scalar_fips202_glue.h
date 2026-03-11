#ifndef TAFRAH_MLKEM_NATIVE_SCALAR_FIPS202_GLUE_H
#define TAFRAH_MLKEM_NATIVE_SCALAR_FIPS202_GLUE_H

#include <stddef.h>
#include <string.h>

#include "fips202.h"

typedef keccak_state mlk_shake128ctx;

static inline void mlk_shake128_init(mlk_shake128ctx *state)
{
  memset(state, 0, sizeof(*state));
}

static inline void mlk_shake128_absorb_once(mlk_shake128ctx *state,
                                            const uint8_t *in,
                                            size_t inlen)
{
  shake128_absorb(state, in, inlen);
}

static inline void mlk_shake128_release(mlk_shake128ctx *state)
{
  (void)state;
}

#define mlk_shake128_squeezeblocks shake128_squeezeblocks
#define mlk_shake256 shake256
#define mlk_sha3_256 sha3_256
#define mlk_sha3_512 sha3_512

#endif
