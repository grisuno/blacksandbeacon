#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * aes_cfb.c - AES-256-CFB encrypt/decrypt routed through OpenSSL EVP.
 *
 * Public API:
 *   unsigned char* aes256_cfb_encrypt(key, iv, plain, len, &out_len);
 *   unsigned char* aes256_cfb_decrypt(key, iv, cipher, len, &out_len);
 *
 * Both return a malloc'd buffer the caller must free.
 */

/* Shared AES-256-CFB primitive (OpenSSL EVP) — mirrors the CFB128
 * implementation the python C2 uses, so multi-block payloads decrypt
 * identically on both ends. */
static unsigned char* _bsb_evp_crypt(const unsigned char* key, const unsigned char* iv,
                                     const unsigned char* data, size_t len, int* out_len,
                                     int encrypt_mode) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    unsigned char* buffer = (unsigned char*)malloc(len + 2);
    if (!buffer) { EVP_CIPHER_CTX_free(ctx); return NULL; }
    int outl = 0, outl2 = 0;
    int ok = encrypt_mode
        ? (EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv) == 1
           && EVP_EncryptUpdate(ctx, buffer, &outl, data, (int)len) == 1
           && EVP_EncryptFinal_ex(ctx, buffer + outl, &outl2) == 1)
        : (EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv) == 1
           && EVP_DecryptUpdate(ctx, buffer, &outl, data, (int)len) == 1
           && EVP_DecryptFinal_ex(ctx, buffer + outl, &outl2) == 1);
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { free(buffer); return NULL; }
    *out_len = outl + outl2;
    return buffer;
}

unsigned char* aes256_cfb_encrypt(const unsigned char* key, const unsigned char* iv,
                                  const unsigned char* plaintext, size_t len, int* out_len) {
    return _bsb_evp_crypt(key, iv, plaintext, len, out_len, 1);
}

unsigned char* aes256_cfb_decrypt(const unsigned char* key, const unsigned char* iv,
                                  const unsigned char* ciphertext, size_t len, int* out_len) {
    unsigned char* plaintext = _bsb_evp_crypt(key, iv, ciphertext, len, out_len, 0);
    if (plaintext) plaintext[*out_len] = '\0';
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