/*
 * Auto-generated C struct definitions from config/schema.json
 * DO NOT EDIT MANUALLY - run config/generate_parsers.py to regenerate
 */
#ifndef BSB_CONFIG_AUTOGEN_H
#define BSB_CONFIG_AUTOGEN_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char url[513];  /* C2 base URL */
    char uri[257];  /* URI path before client ID */
    char client_id[65];  /* Beacon identifier */
    char report_uri[257];  /* URI path for reporting results */
    int port;  /* C2 server port */
    char log_dir[257];  /* Directory for log files */
    char upload_dir[257];  /* Directory for BOF uploads */
} bsb_c2_t;

typedef struct {
    char aes_key_hex[257];  /* Legacy raw AES key (64 hex chars). Used for backward compat if master_key_hex not provided. */
    char master_key_hex[257];  /* Master secret for HKDF key derivation (64 hex chars = 32 bytes) */
    char mode[257];  /* Encryption mode */
    int replay_window_seconds;  /* Replay protection time window in seconds */
} bsb_crypto_t;

typedef struct {
    int sleep_seconds;  /* Base poll interval in seconds */
    int jitter_percent;  /* Jitter percentage applied to sleep interval */
    int curl_timeout_seconds;  /* Total curl timeout in seconds */
    int curl_connect_timeout_seconds;  /* Curl connection timeout in seconds */
} bsb_timing_t;

typedef struct {
    char user_agents[16][257];  /* List of User-Agent strings for rotation */
    int user_agents_count;
    int verify_tls;  /* Whether to verify TLS certificates */
    char cert_fingerprint_sha256[257];  /* Certificate fingerprint for pinning (64 hex chars). Empty = TOFU mode. */
} bsb_network_t;

typedef struct {
    int download_chunk_size;  /* BOF download buffer size in bytes */
    int output_buffer_size;  /* BOF output buffer size in bytes */
} bsb_bof_t;

typedef struct {
    int base_seconds;  /* Initial backoff sleep on failure */
    int max_seconds;  /* Maximum backoff sleep cap */
} bsb_backoff_t;

typedef struct {
    int max_workers;  /* C2 server thread pool size */
    int hmac_enabled;  /* Enable HMAC authentication */
} bsb_server_t;

typedef struct {
    bsb_c2_t c2;
    bsb_crypto_t crypto;
    bsb_timing_t timing;
    bsb_network_t network;
    bsb_bof_t bof;
    bsb_backoff_t backoff;
    bsb_server_t server;
    char path[512];
} bsb_config_t;

/* Load config from path. Returns 0 on success, -1 on error. */
int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);

/* Load from BSB_CONFIG env or default path. */
int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);

/* Compute a sleep duration with jitter applied. Returns seconds. */
int bsb_config_sleep_seconds(const bsb_config_t *cfg);

#endif /* BSB_CONFIG_AUTOGEN_H */