# Symbols (page 4 of 4)
Previous: [SYMBOLS_p3.md](SYMBOLS_p3.md)

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `test_getrandom_fallback_path` | method | `tests/test_iv_generation.py:113` | `def test_getrandom_fallback_path(self)` |
| `test_getrandom_flags_grnd_nonblock` | method | `tests/test_iv_generation.py:177` | `def test_getrandom_flags_grnd_nonblock(self)` |
| `test_iv_length_is_16_bytes_not_mutated` | method | `tests/test_iv_generation.py:131` | `def test_iv_length_is_16_bytes_not_mutated(self)` |
| `test_iv_not_all_zeros` | method | `tests/test_iv_generation.py:146` | `def test_iv_not_all_zeros(self)` |
| `test_rand_bytes_return_value_checked` | method | `tests/test_iv_generation.py:171` | `def test_rand_bytes_return_value_checked(self)` |
| `test_rand_bytes_success_path` | method | `tests/test_iv_generation.py:104` | `def test_rand_bytes_success_path(self)` |
| `test_urandom_blocks_on_low_entropy` | method | `tests/test_iv_generation.py:163` | `def test_urandom_blocks_on_low_entropy(self)` |
| `bsb_generate_secure_iv` | function | `tests/test_iv_generation_c.c:74` | `extern int bsb_generate_secure_iv(unsigned char *iv_out);` |
| `main` | function | `tests/test_iv_generation_c.c:78` | `int main(void)` |
| `test_beacon_common_has_iv_function` | function | `tests/test_iv_generation_c.c:71` | `static void test_beacon_common_has_iv_function(void **state)` |
| `test_generate_secure_iv_different_each_call` | function | `tests/test_iv_generation_c.c:31` | `static void test_generate_secure_iv_different_each_call(void **state)` |
| `test_generate_secure_iv_length` | function | `tests/test_iv_generation_c.c:54` | `static void test_generate_secure_iv_length(void **state)` |
| `test_generate_secure_iv_null_input` | function | `tests/test_iv_generation_c.c:47` | `static void test_generate_secure_iv_null_input(void **state)` |
| `test_generate_secure_iv_success` | function | `tests/test_iv_generation_c.c:19` | `static void test_generate_secure_iv_success(void **state)` |
| `TestReplayProtectionBeaconBehavior` | class | `tests/test_replay_protection.py:108` | `class TestReplayProtectionBeaconBehavior` |
| `TestReplayProtectionConfig` | class | `tests/test_replay_protection.py:29` | `class TestReplayProtectionConfig` |
| `TestReplayProtectionIntegration` | class | `tests/test_replay_protection.py:124` | `class TestReplayProtectionIntegration` |
| `TestReplayProtectionMutationResistance` | class | `tests/test_replay_protection.py:140` | `class TestReplayProtectionMutationResistance` |
| `TestReplayProtectionPayloadFormat` | class | `tests/test_replay_protection.py:63` | `class TestReplayProtectionPayloadFormat` |
| `TestReplayProtectionServerVerification` | class | `tests/test_replay_protection.py:81` | `class TestReplayProtectionServerVerification` |
| `test_beacon_includes_timestamp_in_payload` | method | `tests/test_replay_protection.py:119` | `def test_beacon_includes_timestamp_in_payload(self)` |
| `test_beacon_increments_counter_per_message` | method | `tests/test_replay_protection.py:111` | `def test_beacon_increments_counter_per_message(self)` |
| `test_beacon_resets_counter_on_restart` | method | `tests/test_replay_protection.py:115` | `def test_beacon_resets_counter_on_restart(self)` |
| `test_config_custom_replay_window` | method | `tests/test_replay_protection.py:43` | `def test_config_custom_replay_window(self)` |
| `test_config_defaults_include_replay_window` | method | `tests/test_replay_protection.py:32` | `def test_config_defaults_include_replay_window(self)` |
| `test_config_replay_window_validation_positive` | method | `tests/test_replay_protection.py:53` | `def test_config_replay_window_validation_positive(self)` |
| `test_counter_comparison_not_mutated` | method | `tests/test_replay_protection.py:143` | `def test_counter_comparison_not_mutated(self)` |
| `test_counter_increment_not_mutated` | method | `tests/test_replay_protection.py:173` | `def test_counter_increment_not_mutated(self)` |
| `test_counter_reset_on_new_session` | method | `tests/test_replay_protection.py:179` | `def test_counter_reset_on_new_session(self)` |
| `test_encrypt_includes_counter_and_timestamp` | method | `tests/test_replay_protection.py:66` | `def test_encrypt_includes_counter_and_timestamp(self)` |
| `test_full_roundtrip_with_replay_protection` | method | `tests/test_replay_protection.py:127` | `def test_full_roundtrip_with_replay_protection(self)` |
| `test_hmac_covers_counter_and_timestamp` | method | `tests/test_replay_protection.py:184` | `def test_hmac_covers_counter_and_timestamp(self)` |
| `test_payload_structure_iv_16_counter_8_timestamp_8_ciphertext` | method | `tests/test_replay_protection.py:75` | `def test_payload_structure_iv_16_counter_8_timestamp_8_ciphertext(self)` |
| `test_replay_attack_detected` | method | `tests/test_replay_protection.py:131` | `def test_replay_attack_detected(self)` |
| `test_server_accepts_valid_counter_and_timestamp` | method | `tests/test_replay_protection.py:103` | `def test_server_accepts_valid_counter_and_timestamp(self)` |
| `test_server_rejects_future_timestamp_gt_now_plus_60` | method | `tests/test_replay_protection.py:95` | `def test_server_rejects_future_timestamp_gt_now_plus_60(self)` |
| `test_server_rejects_replay_counter_le_last_seen` | method | `tests/test_replay_protection.py:90` | `def test_server_rejects_replay_counter_le_last_seen(self)` |
| `test_server_rejects_stale_timestamp_lt_now_minus_window` | method | `tests/test_replay_protection.py:99` | `def test_server_rejects_stale_timestamp_lt_now_minus_window(self)` |
| `test_server_tracks_last_seen_counter_per_client` | method | `tests/test_replay_protection.py:84` | `def test_server_tracks_last_seen_counter_per_client(self)` |
| `test_stale_payload_rejected` | method | `tests/test_replay_protection.py:135` | `def test_stale_payload_rejected(self)` |
| `test_timestamp_future_check_not_mutated` | method | `tests/test_replay_protection.py:150` | `def test_timestamp_future_check_not_mutated(self)` |
| `test_timestamp_stale_check_not_mutated` | method | `tests/test_replay_protection.py:161` | `def test_timestamp_stale_check_not_mutated(self)` |

