# Symbols (page 4 of 4)
Previous: [SYMBOLS_p3.md](SYMBOLS_p3.md)

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `main` | function | `tests/test_hkdf_key_derivation_c.c:212` | `int main(void)` |
| `test_aes_key_hex_backward_compat` | function | `tests/test_hkdf_key_derivation_c.c:55` | `static void test_aes_key_hex_backward_compat(void **state)` |
| `test_crypto_struct_has_new_fields` | function | `tests/test_hkdf_key_derivation_c.c:200` | `static void test_crypto_struct_has_new_fields(void **state)` |
| `test_deterministic_derivation` | function | `tests/test_hkdf_key_derivation_c.c:165` | `static void test_deterministic_derivation(void **state)` |
| `test_invalid_master_key_hex_length_fails` | function | `tests/test_hkdf_key_derivation_c.c:115` | `static void test_invalid_master_key_hex_length_fails(void **state)` |
| `test_key_separation` | function | `tests/test_hkdf_key_derivation_c.c:139` | `static void test_key_separation(void **state)` |
| `test_master_key_hex_loads_from_config` | function | `tests/test_hkdf_key_derivation_c.c:19` | `static void test_master_key_hex_loads_from_config(void **state)` |
| `test_missing_both_keys_fails` | function | `tests/test_hkdf_key_derivation_c.c:90` | `static void test_missing_both_keys_fails(void **state)` |
| `main` | function | `tests/test_install_deploy.py:129` | `def main()` |
| `make_all` | function | `tests/test_install_deploy.py:23` | `def make_all()` |
| `run_beacon` | function | `tests/test_install_deploy.py:29` | `def run_beacon(binary, cwd)` |
| `test_build_beacon_lands_alongside_config` | function | `tests/test_install_deploy.py:56` | `def test_build_beacon_lands_alongside_config()` |
| `test_clean_removes_everything` | function | `tests/test_install_deploy.py:103` | `def test_clean_removes_everything()` |
| `test_staged_beacon_runs_from_any_cwd` | function | `tests/test_install_deploy.py:75` | `def test_staged_beacon_runs_from_any_cwd()` |
| `test_staged_bofs_are_present` | function | `tests/test_install_deploy.py:90` | `def test_staged_bofs_are_present()` |
| `test_staged_files_have_correct_modes` | function | `tests/test_install_deploy.py:67` | `def test_staged_files_have_correct_modes()` |
| `TestIVGenerationCBehavior` | class | `tests/test_iv_generation.py:101` | `class TestIVGenerationCBehavior` |
| `TestIVGenerationConfig` | class | `tests/test_iv_generation.py:26` | `class TestIVGenerationConfig` |
| `TestIVGenerationPython` | class | `tests/test_iv_generation.py:42` | `class TestIVGenerationPython` |
| `TestIVMutationResistance` | class | `tests/test_iv_generation.py:128` | `class TestIVMutationResistance` |
| `test_config_defaults_include_iv_settings` | method | `tests/test_iv_generation.py:29` | `def test_config_defaults_include_iv_settings(self)` |
| `test_decrypt_data_handles_iv_correctly` | method | `tests/test_iv_generation.py:73` | `def test_decrypt_data_handles_iv_correctly(self)` |
| `test_encrypt_data_iv_is_16_bytes` | method | `tests/test_iv_generation.py:58` | `def test_encrypt_data_iv_is_16_bytes(self)` |
| `test_encrypt_data_uses_os_urandom_for_iv` | method | `tests/test_iv_generation.py:45` | `def test_encrypt_data_uses_os_urandom_for_iv(self)` |
| `test_encrypt_decrypt_roundtrip_with_different_ivs` | method | `tests/test_iv_generation.py:85` | `def test_encrypt_decrypt_roundtrip_with_different_ivs(self)` |
| `test_fail_closed_on_entropy_failure` | method | `tests/test_iv_generation.py:121` | `def test_fail_closed_on_entropy_failure(self)` |
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
| `TestRandomGeneration` | class | `tests/test_runtime_random.py:44` | `class TestRandomGeneration` |
| `TestStageConfigCarriesRuntimeValues` | class | `tests/test_runtime_random.py:99` | `class TestStageConfigCarriesRuntimeValues` |
| `lrc` | function | `tests/test_runtime_random.py:33` | `def lrc(monkeypatch, tmp_path, raw, env)` |
| `test_all_generated_when_nothing_provided` | method | `tests/test_runtime_random.py:45` | `def test_all_generated_when_nothing_provided(self, monkeypatch, tmp_path)` |
| `test_env_wins` | method | `tests/test_runtime_random.py:87` | `def test_env_wins(self, monkeypatch, tmp_path)` |
| `test_explicit_token_no_generation` | method | `tests/test_runtime_random.py:92` | `def test_explicit_token_no_generation(self, monkeypatch, tmp_path)` |
| `test_file_config_values_win_when_provided` | method | `tests/test_runtime_random.py:112` | `def test_file_config_values_win_when_provided(self, monkeypatch, tmp_path)` |
| `test_generated_key_parities` | method | `tests/test_runtime_random.py:54` | `def test_generated_key_parities(self, monkeypatch, tmp_path)` |
| `test_provided_values_preserved` | method | `tests/test_runtime_random.py:73` | `def test_provided_values_preserved(self, monkeypatch, tmp_path)` |
| `test_random_url_points_at_generated_port` | method | `tests/test_runtime_random.py:62` | `def test_random_url_points_at_generated_port(self, monkeypatch, tmp_path)` |
| `test_served_config_matches_runtime` | method | `tests/test_runtime_random.py:100` | `def test_served_config_matches_runtime(self, monkeypatch, tmp_path)` |
| `test_two_runs_differ` | method | `tests/test_runtime_random.py:66` | `def test_two_runs_differ(self, monkeypatch, tmp_path)` |
| `TestStageBeacon` | class | `tests/test_stage.py:137` | `class TestStageBeacon` |
| `TestStageCodec` | class | `tests/test_stage.py:67` | `class TestStageCodec` |
| `TestStageConfig` | class | `tests/test_stage.py:161` | `class TestStageConfig` |
| `TestStageOneliner` | class | `tests/test_stage.py:219` | `class TestStageOneliner` |
| `TestStageRouting` | class | `tests/test_stage.py:182` | `class TestStageRouting` |
| `TestStageTLSEndToEnd` | class | `tests/test_stage.py:254` | `class TestStageTLSEndToEnd` |
| `TestStageToken` | class | `tests/test_stage.py:119` | `class TestStageToken` |
| `_self_signed_cert` | function | `tests/test_stage.py:236` | `def _self_signed_cert(td)` |
| `make_state` | function | `tests/test_stage.py:55` | `def make_state(tmpdir, token, beacon)` |
| `test_beacon_file_missing` | method | `tests/test_stage.py:146` | `def test_beacon_file_missing(self, tmp_path)` |
| `test_beacon_not_elf` | method | `tests/test_stage.py:150` | `def test_beacon_not_elf(self, tmp_path)` |
| `test_beacon_path_none` | method | `tests/test_stage.py:156` | `def test_beacon_path_none(self, tmp_path)` |
| `test_beacon_roundtrip` | method | `tests/test_stage.py:138` | `def test_beacon_roundtrip(self, tmp_path)` |
| `test_config_always_available` | method | `tests/test_stage.py:174` | `def test_config_always_available(self, tmp_path, monkeypatch)` |
| `test_config_roundtrip` | method | `tests/test_stage.py:162` | `def test_config_roundtrip(self, tmp_path, monkeypatch)` |
| `test_encode_decode_roundtrip` | method | `tests/test_stage.py:68` | `def test_encode_decode_roundtrip(self)` |
| `test_http_get_beacon_routed` | method | `tests/test_stage.py:183` | `def test_http_get_beacon_routed(self, tmp_path)` |
| `test_http_get_config_routed` | method | `tests/test_stage.py:192` | `def test_http_get_config_routed(self, tmp_path, monkeypatch)` |
| `test_keys_derived_deterministically_from_token` | method | `tests/test_stage.py:88` | `def test_keys_derived_deterministically_from_token(self)` |
| `test_legacy_selector_routed` | method | `tests/test_stage.py:211` | `def test_legacy_selector_routed(self, tmp_path)` |
| `test_missing_auth_header_rejected` | method | `tests/test_stage.py:206` | `def test_missing_auth_header_rejected(self, tmp_path)` |
| `test_missing_token_forbidden` | method | `tests/test_stage.py:120` | `def test_missing_token_forbidden(self, tmp_path)` |
| `test_no_token_configured_fails_closed` | method | `tests/test_stage.py:128` | `def test_no_token_configured_fails_closed(self, tmp_path)` |
| `test_oneliner_embeds_url_and_token` | method | `tests/test_stage.py:220` | `def test_oneliner_embeds_url_and_token(self, tmp_path)` |
| `test_server_payload_crypto_parity` | method | `tests/test_stage.py:94` | `def test_server_payload_crypto_parity(self)` |
| `test_tampered_payload_fails_auth` | method | `tests/test_stage.py:78` | `def test_tampered_payload_fails_auth(self)` |
| `test_tls_roundtrip` | method | `tests/test_stage.py:255` | `def test_tls_roundtrip(self, tmp_path, monkeypatch)` |
| `test_unknown_kind_forbidden` | method | `tests/test_stage.py:132` | `def test_unknown_kind_forbidden(self, tmp_path)` |
| `test_wrong_token_fails_auth` | method | `tests/test_stage.py:72` | `def test_wrong_token_fails_auth(self)` |
| `test_wrong_token_forbidden` | method | `tests/test_stage.py:124` | `def test_wrong_token_forbidden(self, tmp_path)` |
| `test_wrong_token_routed_rejected` | method | `tests/test_stage.py:201` | `def test_wrong_token_routed_rejected(self, tmp_path)` |

