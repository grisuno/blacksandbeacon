#include <openssl/evp.h>
#include <stdlib.h>

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
