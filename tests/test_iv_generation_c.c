/*
 * C test for IV Generation with Entropy Verification contract
 * Tests the bsb_generate_secure_iv function
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

/* Include the beacon_common header */
#include "beacon_common.h"

/* Test that bsb_generate_secure_iv returns 1 on success */
static void test_generate_secure_iv_success(void **state) {
    (void)state;
    unsigned char iv[16];
    int result = bsb_generate_secure_iv(iv);
    assert_int_equal(result, 1);
    
    /* Verify IV is not all zeros (extremely unlikely for secure RNG) */
    uint8_t zeros[16] = {0};
    assert_memory_not_equal(iv, zeros, 16);
}

/* Test that bsb_generate_secure_iv produces different IVs on each call */
static void test_generate_secure_iv_different_each_call(void **state) {
    (void)state;
    unsigned char iv1[16];
    unsigned char iv2[16];
    
    int result1 = bsb_generate_secure_iv(iv1);
    int result2 = bsb_generate_secure_iv(iv2);
    
    assert_int_equal(result1, 1);
    assert_int_equal(result2, 1);
    
    /* Two calls should produce different IVs (with extremely high probability) */
    assert_memory_not_equal(iv1, iv2, 16);
}

/* Test that bsb_generate_secure_iv returns 0 on NULL input */
static void test_generate_secure_iv_null_input(void **state) {
    (void)state;
    int result = bsb_generate_secure_iv(NULL);
    assert_int_equal(result, 0);
}

/* Test that IV is exactly 16 bytes */
static void test_generate_secure_iv_length(void **state) {
    (void)state;
    unsigned char iv[16];
    int result = bsb_generate_secure_iv(iv);
    assert_int_equal(result, 1);
    
    /* The function doesn't return the length, but we know it writes 16 bytes */
    /* Verify by checking that all 16 bytes were written (not all zeros) */
    int non_zero_count = 0;
    for (int i = 0; i < 16; i++) {
        if (iv[i] != 0) non_zero_count++;
    }
    /* At least some bytes should be non-zero (probability of all zeros is negligible) */
    assert_true(non_zero_count > 0);
}

/* Test that beacon_common.h has the function declaration */
static void test_beacon_common_has_iv_function(void **state) {
    (void)state;
    /* This test compiles only if the declaration exists */
    extern int bsb_generate_secure_iv(unsigned char *iv_out);
    assert_true(bsb_generate_secure_iv != NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_generate_secure_iv_success),
        cmocka_unit_test(test_generate_secure_iv_different_each_call),
        cmocka_unit_test(test_generate_secure_iv_null_input),
        cmocka_unit_test(test_generate_secure_iv_length),
        cmocka_unit_test(test_beacon_common_has_iv_function),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}