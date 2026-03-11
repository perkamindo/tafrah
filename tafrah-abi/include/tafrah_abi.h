#ifndef TAFRAH_ABI_H
#define TAFRAH_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TAFRAH_STATUS_OK 0
#define TAFRAH_STATUS_NULL_POINTER 1
#define TAFRAH_STATUS_INVALID_LENGTH 2
#define TAFRAH_STATUS_INVALID_PARAMETER 3
#define TAFRAH_STATUS_VERIFICATION_FAILED 4
#define TAFRAH_STATUS_INTERNAL_ERROR 5
#define TAFRAH_STATUS_NOT_IMPLEMENTED 6

const char *tafrah_version(void);
const char *tafrah_status_string(int status);

size_t tafrah_ml_kem_768_ek_size(void);
size_t tafrah_ml_kem_768_dk_size(void);
size_t tafrah_ml_kem_768_ct_size(void);
size_t tafrah_shared_secret_size(void);

size_t tafrah_ml_dsa_65_vk_size(void);
size_t tafrah_ml_dsa_65_sk_size(void);
size_t tafrah_ml_dsa_65_sig_size(void);

size_t tafrah_slh_dsa_shake_128f_vk_size(void);
size_t tafrah_slh_dsa_shake_128f_sk_size(void);
size_t tafrah_slh_dsa_shake_128f_sig_size(void);

size_t tafrah_falcon_512_vk_size(void);
size_t tafrah_falcon_512_sk_size(void);
size_t tafrah_falcon_512_sig_size(void);

size_t tafrah_falcon_1024_vk_size(void);
size_t tafrah_falcon_1024_sk_size(void);
size_t tafrah_falcon_1024_sig_size(void);

size_t tafrah_hqc_128_ek_size(void);
size_t tafrah_hqc_128_dk_size(void);
size_t tafrah_hqc_128_ct_size(void);
size_t tafrah_hqc_128_ss_size(void);

size_t tafrah_hqc_192_ek_size(void);
size_t tafrah_hqc_192_dk_size(void);
size_t tafrah_hqc_192_ct_size(void);
size_t tafrah_hqc_192_ss_size(void);

size_t tafrah_hqc_256_ek_size(void);
size_t tafrah_hqc_256_dk_size(void);
size_t tafrah_hqc_256_ct_size(void);
size_t tafrah_hqc_256_ss_size(void);

int tafrah_ml_kem_768_keygen(uint8_t *ek_out, size_t ek_len,
                             uint8_t *dk_out, size_t dk_len);
int tafrah_ml_kem_768_encapsulate(const uint8_t *ek_ptr, size_t ek_len,
                                  uint8_t *ct_out, size_t ct_len,
                                  uint8_t *ss_out, size_t ss_len);
int tafrah_ml_kem_768_decapsulate(const uint8_t *dk_ptr, size_t dk_len,
                                  const uint8_t *ct_ptr, size_t ct_len,
                                  uint8_t *ss_out, size_t ss_len);

int tafrah_ml_dsa_65_keygen(uint8_t *vk_out, size_t vk_len,
                            uint8_t *sk_out, size_t sk_len);
int tafrah_ml_dsa_65_sign(const uint8_t *sk_ptr, size_t sk_len,
                          const uint8_t *msg_ptr, size_t msg_len,
                          uint8_t *sig_out, size_t sig_len);
int tafrah_ml_dsa_65_verify(const uint8_t *vk_ptr, size_t vk_len,
                            const uint8_t *msg_ptr, size_t msg_len,
                            const uint8_t *sig_ptr, size_t sig_len);

int tafrah_slh_dsa_shake_128f_keygen(uint8_t *vk_out, size_t vk_len,
                                     uint8_t *sk_out, size_t sk_len);
int tafrah_slh_dsa_shake_128f_sign(const uint8_t *sk_ptr, size_t sk_len,
                                   const uint8_t *msg_ptr, size_t msg_len,
                                   uint8_t *sig_out, size_t sig_len);
int tafrah_slh_dsa_shake_128f_verify(const uint8_t *vk_ptr, size_t vk_len,
                                     const uint8_t *msg_ptr, size_t msg_len,
                                     const uint8_t *sig_ptr, size_t sig_len);

int tafrah_falcon_512_keygen(uint8_t *vk_out, size_t vk_len,
                             uint8_t *sk_out, size_t sk_len);
int tafrah_falcon_512_sign(const uint8_t *sk_ptr, size_t sk_len,
                           const uint8_t *msg_ptr, size_t msg_len,
                           uint8_t *sig_out, size_t sig_capacity,
                           size_t *sig_written);
int tafrah_falcon_512_verify(const uint8_t *vk_ptr, size_t vk_len,
                             const uint8_t *msg_ptr, size_t msg_len,
                             const uint8_t *sig_ptr, size_t sig_len);

int tafrah_falcon_1024_keygen(uint8_t *vk_out, size_t vk_len,
                              uint8_t *sk_out, size_t sk_len);
int tafrah_falcon_1024_sign(const uint8_t *sk_ptr, size_t sk_len,
                            const uint8_t *msg_ptr, size_t msg_len,
                            uint8_t *sig_out, size_t sig_capacity,
                            size_t *sig_written);
int tafrah_falcon_1024_verify(const uint8_t *vk_ptr, size_t vk_len,
                              const uint8_t *msg_ptr, size_t msg_len,
                              const uint8_t *sig_ptr, size_t sig_len);

int tafrah_hqc_128_keygen(uint8_t *ek_out, size_t ek_len,
                          uint8_t *dk_out, size_t dk_len);
int tafrah_hqc_128_encapsulate(const uint8_t *ek_ptr, size_t ek_len,
                               uint8_t *ct_out, size_t ct_len,
                               uint8_t *ss_out, size_t ss_len);
int tafrah_hqc_128_decapsulate(const uint8_t *dk_ptr, size_t dk_len,
                               const uint8_t *ct_ptr, size_t ct_len,
                               uint8_t *ss_out, size_t ss_len);

int tafrah_hqc_192_keygen(uint8_t *ek_out, size_t ek_len,
                          uint8_t *dk_out, size_t dk_len);
int tafrah_hqc_192_encapsulate(const uint8_t *ek_ptr, size_t ek_len,
                               uint8_t *ct_out, size_t ct_len,
                               uint8_t *ss_out, size_t ss_len);
int tafrah_hqc_192_decapsulate(const uint8_t *dk_ptr, size_t dk_len,
                               const uint8_t *ct_ptr, size_t ct_len,
                               uint8_t *ss_out, size_t ss_len);

int tafrah_hqc_256_keygen(uint8_t *ek_out, size_t ek_len,
                          uint8_t *dk_out, size_t dk_len);
int tafrah_hqc_256_encapsulate(const uint8_t *ek_ptr, size_t ek_len,
                               uint8_t *ct_out, size_t ct_len,
                               uint8_t *ss_out, size_t ss_len);
int tafrah_hqc_256_decapsulate(const uint8_t *dk_ptr, size_t dk_len,
                               const uint8_t *ct_ptr, size_t ct_len,
                               uint8_t *ss_out, size_t ss_len);

#ifdef __cplusplus
}
#endif

#endif
