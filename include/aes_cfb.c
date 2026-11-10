/*
 * aes_cfb.c - AES-256-CFB encrypt/decrypt using tiny-AES-c.
 *
 * This implementation matches the CFB-128 mode used by the Python C2 server
 * (cryptography.hazmat.primitives.ciphers.modes.CFB), ensuring cross-language
 * compatibility for both single-block and multi-block messages.
 *
 * Public API:
 *   unsigned char* aes256_cfb_encrypt(key, iv, plain, len, &out_len);
 *   unsigned char* aes256_cfb_decrypt(key, iv, cipher, len, &out_len);
 *
 * Both return a malloc'd buffer the caller must free. The decrypt variant
 * appends a trailing NUL byte for convenience.
 */
#include "aes.h"
#include "aes_cfb.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

unsigned char *aes256_cfb_encrypt(const unsigned char *key, const unsigned char *iv,
                                  const unsigned char *plaintext, size_t len, int *out_len)
{
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    unsigned char *ciphertext = (unsigned char *)malloc(len);
    unsigned char iv_buf[16];
    memcpy(iv_buf, iv, 16);
    size_t i = 0;
    while (i < len)
    {
        unsigned char encrypted_iv[16];
        memcpy(encrypted_iv, iv_buf, 16);
        AES_ECB_encrypt(&ctx, encrypted_iv);
        size_t block_size = (len - i > 16) ? 16 : (len - i);
        for (size_t j = 0; j < block_size; j++)
        {
            ciphertext[i + j] = plaintext[i + j] ^ encrypted_iv[j];
        }
        if (block_size == 16)
        {
            memcpy(iv_buf, &ciphertext[i], 16);
        }
        else
        {
            memcpy(iv_buf, &ciphertext[i], block_size);
            memset(iv_buf + block_size, 0, 16 - block_size);
        }
        i += block_size;
    }
    *out_len = (int)len;
    return ciphertext;
}

unsigned char *aes256_cfb_decrypt(const unsigned char *key, const unsigned char *iv,
                                  const unsigned char *ciphertext, size_t len, int *out_len)
{
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    unsigned char *plaintext = (unsigned char *)malloc(len + 1);
    unsigned char iv_buf[16];
    memcpy(iv_buf, iv, 16);
    size_t i = 0;
    while (i < len)
    {
        unsigned char encrypted_iv[16];
        memcpy(encrypted_iv, iv_buf, 16);
        AES_ECB_encrypt(&ctx, encrypted_iv);
        size_t block_size = (len - i > 16) ? 16 : (len - i);
        for (size_t j = 0; j < block_size; j++)
        {
            plaintext[i + j] = ciphertext[i + j] ^ encrypted_iv[j];
        }
        if (block_size == 16)
        {
            memcpy(iv_buf, &ciphertext[i], 16);
        }
        else
        {
            memcpy(iv_buf, &ciphertext[i], block_size);
            memset(iv_buf + block_size, 0, 16 - block_size);
        }
        i += block_size;
    }
    plaintext[len] = '\0';
    *out_len = (int)len;
    return plaintext;
}

/* --- Replay-protected AES-256-CFB --- */

/* Encrypt with replay protection: prepends counter (8 bytes LE) and timestamp (8 bytes LE)
 * to plaintext before AES-CFB encryption. Returns malloc'd buffer (caller frees). */
unsigned char *aes256_cfb_encrypt_replay(const unsigned char *key, const unsigned char *iv,
                                         const unsigned char *plaintext, size_t len,
                                         uint64_t counter, uint64_t timestamp,
                                         int *out_len)
{
    if (!key || !iv || !plaintext || !out_len) return NULL;

    /* Total plaintext: counter(8) + timestamp(8) + plaintext */
    size_t total_len = 16 + len;
    unsigned char *full_plaintext = (unsigned char *)malloc(total_len);
    if (!full_plaintext) return NULL;

    /* Write counter (little-endian) */
    for (int i = 0; i < 8; i++)
        full_plaintext[i] = (counter >> (i * 8)) & 0xFF;

    /* Write timestamp (little-endian) */
    for (int i = 0; i < 8; i++)
        full_plaintext[8 + i] = (timestamp >> (i * 8)) & 0xFF;

    /* Copy plaintext */
    memcpy(full_plaintext + 16, plaintext, len);

    /* Encrypt with standard CFB */
    unsigned char *ciphertext = aes256_cfb_encrypt(key, iv, full_plaintext, total_len, out_len);
    free(full_plaintext);
    return ciphertext;
}

/* Decrypt with replay protection: decrypts ciphertext, extracts counter and timestamp.
 * Returns malloc'd plaintext (without counter/timestamp), sets *out_counter and *out_timestamp.
 * Returns NULL on decryption failure. */
unsigned char *aes256_cfb_decrypt_replay(const unsigned char *key, const unsigned char *iv,
                                         const unsigned char *ciphertext, size_t len,
                                         uint64_t *out_counter, uint64_t *out_timestamp,
                                         int *out_len)
{
    if (!key || !iv || !ciphertext || !out_counter || !out_timestamp || !out_len)
        return NULL;

    if (len < 16) return NULL;  /* Must have at least counter + timestamp */

    /* Decrypt with standard CFB */
    int decrypted_len = 0;
    unsigned char *full_plaintext = aes256_cfb_decrypt(key, iv, ciphertext, len, &decrypted_len);
    if (!full_plaintext) return NULL;

    if (decrypted_len < 16)
    {
        free(full_plaintext);
        return NULL;
    }

    /* Extract counter (little-endian) */
    uint64_t counter = 0;
    for (int i = 0; i < 8; i++)
        counter |= ((uint64_t)full_plaintext[i]) << (i * 8);

    /* Extract timestamp (little-endian) */
    uint64_t timestamp = 0;
    for (int i = 0; i < 8; i++)
        timestamp |= ((uint64_t)full_plaintext[8 + i]) << (i * 8);

    *out_counter = counter;
    *out_timestamp = timestamp;

    /* Return plaintext without counter/timestamp */
    size_t plaintext_len = decrypted_len - 16;
    unsigned char *plaintext = (unsigned char *)malloc(plaintext_len + 1);
    if (!plaintext)
    {
        free(full_plaintext);
        return NULL;
    }
    memcpy(plaintext, full_plaintext + 16, plaintext_len);
    plaintext[plaintext_len] = '\0';
    *out_len = (int)plaintext_len;

    free(full_plaintext);
    return plaintext;
}