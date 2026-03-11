#ifndef TAFRAH_MLKEM_NATIVE_SCALAR_FIPS202X4_GLUE_H
#define TAFRAH_MLKEM_NATIVE_SCALAR_FIPS202X4_GLUE_H

#include <stddef.h>
#include <string.h>

#include "fips202.h"

typedef struct {
  keccak_state lanes[4];
} mlk_shake128x4ctx;

static inline void mlk_shake128x4_init(mlk_shake128x4ctx *state)
{
  memset(state, 0, sizeof(*state));
}

static inline void mlk_shake128x4_absorb_once(mlk_shake128x4ctx *state,
                                              const uint8_t *in0,
                                              const uint8_t *in1,
                                              const uint8_t *in2,
                                              const uint8_t *in3,
                                              size_t inlen)
{
  shake128_absorb(&state->lanes[0], in0, inlen);
  shake128_absorb(&state->lanes[1], in1, inlen);
  shake128_absorb(&state->lanes[2], in2, inlen);
  shake128_absorb(&state->lanes[3], in3, inlen);
}

static inline void mlk_shake128x4_squeezeblocks(uint8_t *out0,
                                                uint8_t *out1,
                                                uint8_t *out2,
                                                uint8_t *out3,
                                                size_t nblocks,
                                                mlk_shake128x4ctx *state)
{
  shake128_squeezeblocks(out0, nblocks, &state->lanes[0]);
  shake128_squeezeblocks(out1, nblocks, &state->lanes[1]);
  shake128_squeezeblocks(out2, nblocks, &state->lanes[2]);
  shake128_squeezeblocks(out3, nblocks, &state->lanes[3]);
}

static inline void mlk_shake128x4_release(mlk_shake128x4ctx *state)
{
  (void)state;
}

static inline void mlk_shake256x4(uint8_t *out0,
                                  uint8_t *out1,
                                  uint8_t *out2,
                                  uint8_t *out3,
                                  size_t outlen,
                                  const uint8_t *in0,
                                  const uint8_t *in1,
                                  const uint8_t *in2,
                                  const uint8_t *in3,
                                  size_t inlen)
{
  shake256(out0, outlen, in0, inlen);
  shake256(out1, outlen, in1, inlen);
  shake256(out2, outlen, in2, inlen);
  shake256(out3, outlen, in3, inlen);
}

#endif
