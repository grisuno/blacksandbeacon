/*
 * aes_cfb.c - AES-256-CFB encrypt/decrypt, extracted from the
 * original beacon implementation.
 *
 * This is the same algorithm the v1 beacon uses to wrap C2
 * commands and results. The C2 server in c2/server.py implements
 * the matching Python side using the `cryptography` library.
 *
 * Public API:
 *   unsigned char* aes256_cfb_encrypt(key, iv, plain, len, &out_len);
 *   unsigned char* aes256_cfb_decrypt(key, iv, cipher, len, &out_len);
 *
 * Both return a malloc'd buffer the caller must free. The
 * decrypt variant appends a trailing NUL byte for convenience.
 */
#include "aes.h"
#include <stdlib.h>
#include <string.h>

unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
                                  const unsigned char* plaintext, size_t len, int* out_len) {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    unsigned char* ciphertext = (unsigned char*)malloc(len);
    unsigned char iv_buf[16];
    memcpy(iv_buf, iv, 16);
    size_t i = 0;
    while (i < len) {
        unsigned char encrypted_iv[16];
        memcpy(encrypted_iv, iv_buf, 16);
        AES_ECB_encrypt(&ctx, encrypted_iv);
        size_t block_size = (len - i > 16) ? 16 : (len - i);
        for (size_t j = 0; j < block_size; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ encrypted_iv[j];
        }
        if (block_size == 16) {
            memcpy(iv_buf, &ciphertext[i], 16);
        } else {
            memcpy(iv_buf, &ciphertext[i], block_size);
            memset(iv_buf + block_size, 0, 16 - block_size);
        }
        i += block_size;
    }
    *out_len = (int)len;
    return ciphertext;
}

unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
                                  const unsigned char* ciphertext, size_t len, int* out_len) {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    unsigned char* plaintext = (unsigned char*)malloc(len + 1);
    unsigned char iv_buf[16];
    memcpy(iv_buf, iv, 16);
    size_t i = 0;
    while (i < len) {
        unsigned char encrypted_iv[16];
        memcpy(encrypted_iv, iv_buf, 16);
        AES_ECB_encrypt(&ctx, encrypted_iv);
        size_t block_size = (len - i > 16) ? 16 : (len - i);
        for (size_t j = 0; j < block_size; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ encrypted_iv[j];
        }
        if (block_size == 16) {
            memcpy(iv_buf, &ciphertext[i], 16);
        } else {
            memcpy(iv_buf, &ciphertext[i], block_size);
            memset(iv_buf + block_size, 0, 16 - block_size);
        }
        i += block_size;
    }
    plaintext[len] = '\0';
    *out_len = (int)len;
    return plaintext;
}
