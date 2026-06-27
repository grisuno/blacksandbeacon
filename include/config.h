/*
 * config.h - Runtime configuration loaded from config/config.json.
 *
 * The beacon reads its C2 URL, AES key, sleep interval, and
 * timeouts from a JSON file at startup instead of baking them
 * into the binary. The path defaults to ./config/config.json
 * and can be overridden with the BSB_CONFIG environment variable.
 *
 * The parser is intentionally small (no cJSON dependency for the
 * beacon itself) but uses cJSON if available. Define BSB_USE_CJSON
 * at build time to enable the cJSON path.
 */
#ifndef BSB_CONFIG_H
#define BSB_CONFIG_H

#include <stdint.h>
#include <stddef.h>

#define BSB_CONFIG_PATH_DEFAULT "config/config.json"
#define BSB_CONFIG_PATH_ENV     "BSB_CONFIG"
#define BSB_MAX_URL             512
#define BSB_MAX_URI             128
#define BSB_MAX_CLIENT_ID       64
#define BSB_AES_KEY_HEX_LEN     64   /* 32 bytes -> 64 hex chars */
#define BSB_AES_KEY_BYTES       32
#define BSB_MAX_USER_AGENTS     16
#define BSB_USER_AGENT_LEN      256
#define BSB_REPORT_URI_DEFAULT  "/report/"

typedef struct {
    char  url[BSB_MAX_URL];
    char  uri[BSB_MAX_URI];
    char  client_id[BSB_MAX_CLIENT_ID];
    char  report_uri[BSB_MAX_URI];
} bsb_c2_t;

typedef struct {
    uint8_t key[BSB_AES_KEY_BYTES];
    char    mode[8];   /* "cfb" (current) or "gcm" (future) */
} bsb_crypto_t;

typedef struct {
    int sleep_seconds;
    int jitter_percent;
    int curl_timeout_seconds;
    int curl_connect_timeout_seconds;
} bsb_timing_t;

typedef struct {
    char user_agents[BSB_MAX_USER_AGENTS][BSB_USER_AGENT_LEN];
    int  count;
    int  verify_tls;   /* 0 = accept self-signed, 1 = verify */
} bsb_network_t;

typedef struct {
    int download_chunk_size;
    int output_buffer_size;   /* BOF output buffer in bytes (default 65536) */
} bsb_bof_t;

typedef struct {
    int base_seconds;         /* initial sleep on failure (default 6) */
    int max_seconds;          /* cap for exponential backoff (default 300) */
} bsb_backoff_config_t;

typedef struct {
    bsb_c2_t              c2;
    bsb_crypto_t          crypto;
    bsb_timing_t          timing;
    bsb_network_t         network;
    bsb_bof_t             bof;
    bsb_backoff_config_t  backoff;
    char                  path[512];
} bsb_config_t;

/* Load config from path. Returns 0 on success, -1 on error.
 * On error, leaves a human-readable message in `err` (if non-NULL). */
int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen);

/* Load from BSB_CONFIG env or default path. */
int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen);

/* Compute a sleep duration with jitter applied. Returns seconds. */
int bsb_config_sleep_seconds(const bsb_config_t *cfg);

#endif /* BSB_CONFIG_H */
