/*
 * config_harness.c - Test harness for the BSB config loader.
 *
 * Loads config from BSB_CONFIG (or default path) and prints one
 * line per field. The Python tests in test_config.py parse the
 * output to assert behaviour.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void hex_encode(const uint8_t *in, size_t n, char *out) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i]   = h[in[i] >> 4];
        out[2*i+1] = h[in[i] & 0xf];
    }
    out[2*n] = '\0';
}

int main(void) {
    bsb_config_t cfg;
    char err[256] = {0};
    if (bsb_config_load_default(&cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "config error: %s\n", err);
        return 1;
    }

    char key_hex[BSB_AES_KEY_BYTES * 2 + 1];
    hex_encode(cfg.crypto.key, BSB_AES_KEY_BYTES, key_hex);

    printf("c2.url=%s\n", cfg.c2.url);
    printf("c2.uri=%s\n", cfg.c2.uri);
    printf("c2.client_id=%s\n", cfg.c2.client_id);
    printf("c2.report_uri=%s\n", cfg.c2.report_uri);
    printf("crypto.aes_key_hex=%s\n", key_hex);
    printf("crypto.mode=%s\n", cfg.crypto.mode);
    printf("timing.sleep_seconds=%d\n", cfg.timing.sleep_seconds);
    printf("timing.jitter_percent=%d\n", cfg.timing.jitter_percent);
    printf("timing.curl_timeout_seconds=%d\n", cfg.timing.curl_timeout_seconds);
    printf("timing.curl_connect_timeout_seconds=%d\n", cfg.timing.curl_connect_timeout_seconds);
    printf("network.user_agents=%d\n", cfg.network.count);
    printf("network.verify_tls=%d\n", cfg.network.verify_tls);
    printf("bof.download_chunk_size=%d\n", cfg.bof.download_chunk_size);
    printf("sleep_with_jitter=%d\n", bsb_config_sleep_seconds(&cfg));
    return 0;
}
