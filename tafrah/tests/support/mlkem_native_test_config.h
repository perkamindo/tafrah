#ifndef TAFRAH_MLKEM_NATIVE_TEST_CONFIG_H
#define TAFRAH_MLKEM_NATIVE_TEST_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#ifndef MLK_CONFIG_PARAMETER_SET
#define MLK_CONFIG_PARAMETER_SET 768
#endif

#if MLK_CONFIG_PARAMETER_SET == 512
#define MLK_CONFIG_NAMESPACE_PREFIX PQCP_MLKEM_NATIVE_MLKEM512_C
#elif MLK_CONFIG_PARAMETER_SET == 768
#define MLK_CONFIG_NAMESPACE_PREFIX PQCP_MLKEM_NATIVE_MLKEM768_C
#elif MLK_CONFIG_PARAMETER_SET == 1024
#define MLK_CONFIG_NAMESPACE_PREFIX PQCP_MLKEM_NATIVE_MLKEM1024_C
#else
#error unsupported ML-KEM parameter set
#endif

#define MLK_CONFIG_FIPS202_CUSTOM_HEADER "mlkem_native_scalar_fips202_glue.h"
#define MLK_CONFIG_FIPS202X4_CUSTOM_HEADER "mlkem_native_scalar_fips202x4_glue.h"
#define MLK_CONFIG_NO_ASM
#define MLK_CONFIG_CUSTOM_RANDOMBYTES
#define MLK_CONFIG_CUSTOM_ZEROIZE

static inline void mlk_zeroize(void *ptr, size_t len)
{
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (len-- > 0) {
    *p++ = 0;
  }
}

void mlkem_native_test_randombytes(uint8_t *ptr, size_t len);

static inline void mlk_randombytes(uint8_t *ptr, size_t len)
{
  mlkem_native_test_randombytes(ptr, len);
}

#endif
