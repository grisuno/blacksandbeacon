/*
 * crypto_harness.c - Roundtrip test harness for AES-256-CFB.
 *
 * Used by tests/test_crypto.py to validate the AES path the
 * beacon and C2 server use for command/result encryption.
 */
#include "aes_cfb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen) {
    size_t hlen = strlen(hex);
    if (hlen != outlen * 2) return -1;
    for (size_t i = 0; i < outlen; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (unsigned char)b;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *key_hex = NULL;
    const char *plain = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--key") && i + 1 < argc) key_hex = argv[++i];
        else if (!strcmp(argv[i], "--plain") && i + 1 < argc) plain = argv[++i];
    }
    if (!key_hex || !plain) {
        fprintf(stderr, "usage: %s --key <64hex> --plain <text>\n", argv[0]);
        return 2;
    }

    unsigned char key[32];
    if (hex_to_bytes(key_hex, key, 32) != 0) {
        printf("FAIL:bad-key\n");
        return 1;
    }
    size_t plen = strlen(plain);

    unsigned char iv[16] = {0};
    for (int i = 0; i < 16; i++) iv[i] = (unsigned char)(i * 17 + 3);

    int enc_len = 0;
    unsigned char *cipher = aes256_cfb_encrypt(key, iv,
                                               (const unsigned char *)plain, plen, &enc_len);
    if (!cipher || enc_len != (int)plen) {
        printf("FAIL:encrypt\n");
        free(cipher);
        return 1;
    }
    int dec_len = 0;
    unsigned char *recovered = aes256_cfb_decrypt(key, iv, cipher, enc_len, &dec_len);
    if (!recovered || dec_len != enc_len) {
        printf("FAIL:decrypt\n");
        free(cipher); free(recovered);
        return 1;
    }
    if (memcmp(recovered, plain, plen) != 0) {
        printf("FAIL:roundtrip\n");
        free(cipher); free(recovered);
        return 1;
    }
    /* Output ciphertext as hex so Python tests can pin it. */
    char hex[2048] = {0};
    for (int i = 0; i < enc_len; i++) {
        snprintf(hex + i*2, 3, "%02x", cipher[i]);
    }
    printf("OK %s\n", hex);
    free(cipher); free(recovered);
    return 0;
}
