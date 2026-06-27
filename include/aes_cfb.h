/*
 * aes_cfb.h - Public API for AES-256-CFB used by the beacon and C2.
 */
#ifndef BSB_AES_CFB_H
#define BSB_AES_CFB_H

#include <stddef.h>

unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
                                  const unsigned char* plaintext, size_t len, int* out_len);
unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
                                  const unsigned char* ciphertext, size_t len, int* out_len);

#endif
