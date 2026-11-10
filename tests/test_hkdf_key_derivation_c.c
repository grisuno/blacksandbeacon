/*
 * C test for HKDF Key Derivation contract
 * Tests the config loading and HKDF key derivation logic
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/* Include the config header */
#include "config.h"

/* Test that master_key_hex field exists and can be loaded */
static void test_master_key_hex_loads_from_config(void **state) {
    (void)state;
    /* Create a temporary config file with master_key_hex */
    const char *config_content = 
        "{"
        "  \"crypto\": {"
        "    \"master_key_hex\": \"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\""
        "  }"
        "}";
    
    FILE *f = fopen("/tmp/test_master_key.json", "w");
    assert_non_null(f);
    fputs(config_content, f);
    fclose(f);
    
    bsb_config_t cfg;
    char err[512];
    int r = bsb_config_load("/tmp/test_master_key.json", &cfg, err, sizeof(err));
    assert_int_equal(r, 0);
    
    /* Verify master_key was parsed */
    assert_memory_equal(cfg.crypto.master_key, 
        "\xa1\xb2\xc3\xd4\xe5\xf6\xa7\xb8\xc9\xd0\xe1\xf2\xa3\xb4\xc5\xd6"
        "\xe7\xf8\xa9\xb0\xc1\xd2\xe3\xf4\xa5\xb6\xc7\xd8\xe9\xf0\xa1\xb2", 
        BSB_AES_KEY_BYTES);
    
    /* Verify derived keys are non-zero and different */
    uint8_t zeros[BSB_AES_KEY_BYTES] = {0};
    assert_memory_not_equal(cfg.crypto.encryption_key, zeros, BSB_AES_KEY_BYTES);
    assert_memory_not_equal(cfg.crypto.hmac_key, zeros, BSB_AES_KEY_BYTES);
    assert_memory_not_equal(cfg.crypto.encryption_key, cfg.crypto.hmac_key, BSB_AES_KEY_BYTES);
    
    unlink("/tmp/test_master_key.json");
}

/* Test that legacy aes_key_hex still works (backward compat) */
static void test_aes_key_hex_backward_compat(void **state) {
    (void)state;
    const char *config_content = 
        "{"
        "  \"crypto\": {"
        "    \"aes_key_hex\": \"b1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\""
        "  }"
        "}";
    
    FILE *f = fopen("/tmp/test_aes_key.json", "w");
    assert_non_null(f);
    fputs(config_content, f);
    fclose(f);
    
    bsb_config_t cfg;
    char err[512];
    int r = bsb_config_load("/tmp/test_aes_key.json", &cfg, err, sizeof(err));
    assert_int_equal(r, 0);
    
    /* Verify legacy key was parsed */
    assert_memory_equal(cfg.crypto.key, 
        "\xb1\xb2\xc3\xd4\xe5\xf6\xa7\xb8\xc9\xd0\xe1\xf2\xa3\xb4\xc5\xd6"
        "\xe7\xf8\xa9\xb0\xc1\xd2\xe3\xf4\xa5\xb6\xc7\xd8\xe9\xf0\xa1\xb2", 
        BSB_AES_KEY_BYTES);
    
    /* Verify derived keys are non-zero and different */
    uint8_t zeros[BSB_AES_KEY_BYTES] = {0};
    assert_memory_not_equal(cfg.crypto.encryption_key, zeros, BSB_AES_KEY_BYTES);
    assert_memory_not_equal(cfg.crypto.hmac_key, zeros, BSB_AES_KEY_BYTES);
    assert_memory_not_equal(cfg.crypto.encryption_key, cfg.crypto.hmac_key, BSB_AES_KEY_BYTES);
    
    unlink("/tmp/test_aes_key.json");
}

/* Test that missing both keys fails */
static void test_missing_both_keys_fails(void **state) {
    (void)state;
    const char *config_content = 
        "{"
        "  \"crypto\": {"
        "    \"master_key_hex\": \"\","
        "    \"aes_key_hex\": \"\""
        "  }"
        "}";
    
    FILE *f = fopen("/tmp/test_no_keys.json", "w");
    assert_non_null(f);
    fputs(config_content, f);
    fclose(f);
    
    bsb_config_t cfg;
    char err[512];
    int r = bsb_config_load("/tmp/test_no_keys.json", &cfg, err, sizeof(err));
    assert_int_equal(r, -1);
    assert_string_equal(err, "crypto.master_key_hex or crypto.aes_key_hex missing or invalid");
    
    unlink("/tmp/test_no_keys.json");
}

/* Test that invalid master_key_hex length fails */
static void test_invalid_master_key_hex_length_fails(void **state) {
    (void)state;
    const char *config_content = 
        "{"
        "  \"crypto\": {"
        "    \"master_key_hex\": \"abc\""
        "  }"
        "}";
    
    FILE *f = fopen("/tmp/test_bad_master_key.json", "w");
    assert_non_null(f);
    fputs(config_content, f);
    fclose(f);
    
    bsb_config_t cfg;
    char err[512];
    int r = bsb_config_load("/tmp/test_bad_master_key.json", &cfg, err, sizeof(err));
    assert_int_equal(r, -1);
    assert_true(strstr(err, "master_key_hex") != NULL);
    
    unlink("/tmp/test_bad_master_key.json");
}

/* Test that encryption_key and hmac_key are different for same master key (key separation) */
static void test_key_separation(void **state) {
    (void)state;
    const char *config_content = 
        "{"
        "  \"crypto\": {"
        "    \"master_key_hex\": \"c1c2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\""
        "  }"
        "}";
    
    FILE *f = fopen("/tmp/test_key_sep.json", "w");
    assert_non_null(f);
    fputs(config_content, f);
    fclose(f);
    
    bsb_config_t cfg;
    char err[512];
    int r = bsb_config_load("/tmp/test_key_sep.json", &cfg, err, sizeof(err));
    assert_int_equal(r, 0);
    
    /* Verify encryption_key != hmac_key (key separation) */
    assert_memory_not_equal(cfg.crypto.encryption_key, cfg.crypto.hmac_key, BSB_AES_KEY_BYTES);
    
    unlink("/tmp/test_key_sep.json");
}

/* Test that same master_key produces same derived keys (deterministic) */
static void test_deterministic_derivation(void **state) {
    (void)state;
    const char *config_content = 
        "{"
        "  \"crypto\": {"
        "    \"master_key_hex\": \"d1d2d3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\""
        "  }"
        "}";
    
    FILE *f1 = fopen("/tmp/test_det1.json", "w");
    assert_non_null(f1);
    fputs(config_content, f1);
    fclose(f1);
    
    FILE *f2 = fopen("/tmp/test_det2.json", "w");
    assert_non_null(f2);
    fputs(config_content, f2);
    fclose(f2);
    
    bsb_config_t cfg1, cfg2;
    char err[512];
    int r1 = bsb_config_load("/tmp/test_det1.json", &cfg1, err, sizeof(err));
    int r2 = bsb_config_load("/tmp/test_det2.json", &cfg2, err, sizeof(err));
    assert_int_equal(r1, 0);
    assert_int_equal(r2, 0);
    
    /* Derived keys should be identical */
    assert_memory_equal(cfg1.crypto.encryption_key, cfg2.crypto.encryption_key, BSB_AES_KEY_BYTES);
    assert_memory_equal(cfg1.crypto.hmac_key, cfg2.crypto.hmac_key, BSB_AES_KEY_BYTES);
    
    unlink("/tmp/test_det1.json");
    unlink("/tmp/test_det2.json");
}

/* Test that crypto struct has new fields */
static void test_crypto_struct_has_new_fields(void **state) {
    (void)state;
    bsb_crypto_t crypto;
    /* This test compiles only if the fields exist */
    memset(crypto.master_key, 0, BSB_AES_KEY_BYTES);
    memset(crypto.encryption_key, 0, BSB_AES_KEY_BYTES);
    memset(crypto.hmac_key, 0, BSB_AES_KEY_BYTES);
    assert_memory_equal(crypto.master_key, (uint8_t[BSB_AES_KEY_BYTES]){0}, BSB_AES_KEY_BYTES);
    assert_memory_equal(crypto.encryption_key, (uint8_t[BSB_AES_KEY_BYTES]){0}, BSB_AES_KEY_BYTES);
    assert_memory_equal(crypto.hmac_key, (uint8_t[BSB_AES_KEY_BYTES]){0}, BSB_AES_KEY_BYTES);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_master_key_hex_loads_from_config),
        cmocka_unit_test(test_aes_key_hex_backward_compat),
        cmocka_unit_test(test_missing_both_keys_fails),
        cmocka_unit_test(test_invalid_master_key_hex_length_fails),
        cmocka_unit_test(test_key_separation),
        cmocka_unit_test(test_deterministic_derivation),
        cmocka_unit_test(test_crypto_struct_has_new_fields),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}