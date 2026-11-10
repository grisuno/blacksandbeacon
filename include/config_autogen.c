/*
 * Auto-generated C config parser from config/schema.json
 * DO NOT EDIT MANUALLY - run config/generate_parsers.py to regenerate
 */
#define _POSIX_C_SOURCE 200809L
#include "config_autogen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

/* --- file slurper --- */
static char *slurp(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return NULL; }
    buf[n] = '\0';
    fclose(f);
    *out_len = (size_t)n;
    return buf;
}

/* --- lexer-style cursor helpers --- */
static const char *skip_ws(const char *p, const char *end)
{
    while (p < end && isspace((unsigned char)*p)) p++;
    return p;
}

static int read_string(const char **pp, const char *end, char *out, size_t outsz)
{
    const char *p = skip_ws(*pp, end);
    if (p >= end || *p != '"') return 0;
    p++;
    size_t i = 0;
    while (p < end && *p != '"') {
        char ch = *p++;
        if (ch == '\\' && p < end) {
            char esc = *p++;
            switch (esc) {
                case 'n': ch = '\n'; break;
                case 't': ch = '\t'; break;
                case 'r': ch = '\r'; break;
                case '"': ch = '"'; break;
                case '\\': ch = '\\'; break;
                default: ch = esc; break;
            }
        }
        if (i + 1 < outsz) out[i++] = ch;
    }
    if (p >= end) return 0;
    p++;
    if (outsz) out[i < outsz ? i : outsz - 1] = '\0';
    *pp = p;
    return 1;
}

static int read_int(const char **pp, const char *end, int *out)
{
    const char *p = skip_ws(*pp, end);
    if (p >= end) return 0;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    if (p >= end || !isdigit((unsigned char)*p)) return 0;
    long v = 0;
    while (p < end && isdigit((unsigned char)*p)) {
        v = v * 10 + (*p - '0');
        p++;
    }
    *out = (int)(neg ? -v : v);
    *pp = p;
    return 1;
}

static int read_bool(const char **pp, const char *end, int *out)
{
    const char *p = skip_ws(*pp, end);
    if ((end - p) >= 4 && !memcmp(p, "true", 4)) { *out = 1; *pp = p + 4; return 1; }
    if ((end - p) >= 5 && !memcmp(p, "false", 5)) { *out = 0; *pp = p + 5; return 1; }
    return 0;
}

static int expect(const char **pp, const char *end, char c)
{
    const char *p = skip_ws(*pp, end);
    if (p >= end || *p != c) return 0;
    *pp = p + 1;
    return 1;
}

static const char *find_matching_brace(const char *p, const char *end)
{
    if (p >= end || *p != '{') return NULL;
    int depth = 0;
    while (p < end) {
        char c = *p;
        if (c == '"') {
            p++;
            while (p < end && *p != '"') {
                if (*p == '\\' && p + 1 < end) p++;
                p++;
            }
            if (p < end) p++;
            continue;
        }
        if (c == '{') depth++;
        else if (c == '}') { depth--; if (depth == 0) return p; }
        p++;
    }
    return NULL;
}

static const char *skip_value(const char *p, const char *end)
{
    p = skip_ws(p, end);
    if (p >= end) return NULL;
    char c = *p;
    if (c == '"') {
        p++;
        while (p < end && *p != '"') {
            if (*p == '\\' && p + 1 < end) p++;
            p++;
        }
        if (p < end) p++;
        return p;
    }
    if (c == '{') return find_matching_brace(p, end) + 1;
    if (c == '[') {
        int depth = 0;
        while (p < end) {
            char ch = *p;
            if (ch == '"') {
                p++;
                while (p < end && *p != '"') {
                    if (*p == '\\' && p + 1 < end) p++;
                    p++;
                }
                if (p < end) p++;
                continue;
            }
            if (ch == '[') depth++;
            else if (ch == ']') { depth--; if (depth == 0) return p + 1; }
            p++;
        }
        return NULL;
    }
    if (c == 't') return p + 4;
    if (c == 'f') return p + 5;
    if (c == 'n') return p + 4;
    while (p < end && (*p == '-' || isdigit((unsigned char)*p) || *p == '.' || *p == 'e' || *p == 'E' || *p == '+')) p++;
    return p;
}

/* --- hex decode --- */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen)
{
    size_t hlen = strlen(hex);
    if (hlen != outlen * 2) return -1;
    for (size_t i = 0; i < outlen; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

static void parse_c2(const char *p, const char *end, bsb_config_t *cfg)
{
    bsb_c2_t *s = &cfg->c2;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) return;
        if (!expect(&p, end, ':')) return;
        if (!strcmp(key, "url"))
        {
            if (!read_string(&p, end, s->url, sizeof(s->url))) return;
        }
        else if (!strcmp(key, "client_id"))
        {
            if (!read_string(&p, end, s->client_id, sizeof(s->client_id))) return;
        }
        else if (!strcmp(key, "port"))
        {
            if (!read_int(&p, end, &s->port)) return;
        }
        } else {
            p = skip_value(p, end); if (!p) return;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
}

static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg)
{
    bsb_crypto_t *s = &cfg->crypto;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) return;
        if (!expect(&p, end, ':')) return;
        else if (!strcmp(key, "replay_window_seconds"))
        {
            if (!read_int(&p, end, &s->replay_window_seconds)) return;
        }
        } else {
            p = skip_value(p, end); if (!p) return;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
}

static void parse_timing(const char *p, const char *end, bsb_config_t *cfg)
{
    bsb_timing_t *s = &cfg->timing;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) return;
        if (!expect(&p, end, ':')) return;
        if (!strcmp(key, "sleep_seconds"))
        {
            if (!read_int(&p, end, &s->sleep_seconds)) return;
        }
        else if (!strcmp(key, "jitter_percent"))
        {
            if (!read_int(&p, end, &s->jitter_percent)) return;
        }
        else if (!strcmp(key, "curl_timeout_seconds"))
        {
            if (!read_int(&p, end, &s->curl_timeout_seconds)) return;
        }
        else if (!strcmp(key, "curl_connect_timeout_seconds"))
        {
            if (!read_int(&p, end, &s->curl_connect_timeout_seconds)) return;
        }
        } else {
            p = skip_value(p, end); if (!p) return;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
}

static void parse_network(const char *p, const char *end, bsb_config_t *cfg)
{
    bsb_network_t *s = &cfg->network;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) return;
        if (!expect(&p, end, ':')) return;
        if (!strcmp(key, "user_agents"))
        {
            if (!expect(&p, end, '[')) return;
            s->user_agents_count = 0;
            while (1) {
                p = skip_ws(p, end);
                if (p >= end) return;
                if (*p == ']') { p++; break; }
                if (s->user_agents_count < 16) {
                    if (!read_string(&p, end, s->user_agents[s->user_agents_count], 257)) return;
                    s->user_agents_count++;
                } else {
                    char tmp[257];
                    if (!read_string(&p, end, tmp, sizeof(tmp))) return;
                }
                p = skip_ws(p, end);
                if (p < end && *p == ',') p++;
            }
        }
        else if (!strcmp(key, "verify_tls"))
        {
            if (!read_bool(&p, end, &s->verify_tls)) return;
        }
        } else {
            p = skip_value(p, end); if (!p) return;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
}

static void parse_bof(const char *p, const char *end, bsb_config_t *cfg)
{
    bsb_bof_t *s = &cfg->bof;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) return;
        if (!expect(&p, end, ':')) return;
        if (!strcmp(key, "download_chunk_size"))
        {
            if (!read_int(&p, end, &s->download_chunk_size)) return;
        }
        else if (!strcmp(key, "output_buffer_size"))
        {
            if (!read_int(&p, end, &s->output_buffer_size)) return;
        }
        } else {
            p = skip_value(p, end); if (!p) return;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
}

static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg)
{
    bsb_backoff_t *s = &cfg->backoff;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) return;
        if (!expect(&p, end, ':')) return;
        if (!strcmp(key, "base_seconds"))
        {
            if (!read_int(&p, end, &s->base_seconds)) return;
        }
        else if (!strcmp(key, "max_seconds"))
        {
            if (!read_int(&p, end, &s->max_seconds)) return;
        }
        } else {
            p = skip_value(p, end); if (!p) return;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
}

static void parse_server(const char *p, const char *end, bsb_config_t *cfg)
{
    bsb_server_t *s = &cfg->server;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) return;
        if (!expect(&p, end, ':')) return;
        if (!strcmp(key, "max_workers"))
        {
            if (!read_int(&p, end, &s->max_workers)) return;
        }
        else if (!strcmp(key, "hmac_enabled"))
        {
            if (!read_bool(&p, end, &s->hmac_enabled)) return;
        }
        } else {
            p = skip_value(p, end); if (!p) return;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
}

int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen)
{
    if (err && errlen) err[0] = '\0';
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->path, sizeof(cfg->path), "%s", path);

    size_t n = 0;
    char *buf = slurp(path, &n);
    if (!buf)
    {
        if (err && errlen) snprintf(err, errlen, "cannot open %s", path);
        return -1;
    }
    const char *p = buf;
    const char *end = buf + n;

    if (!expect(&p, end, '{'))
    {
        if (err && errlen) snprintf(err, errlen, "expected { at top of file");
        free(buf); return -1;
    }

    while (1)
    {
        p = skip_ws(p, end);
        if (p >= end) break;
        if (*p == '}') break;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key)))
        {
            if (err && errlen) snprintf(err, errlen, "expected section key");
            free(buf); return -1;
        }
        if (!expect(&p, end, ':'))
        {
            if (err && errlen) snprintf(err, errlen, "expected ':' after key %s", key);
            free(buf); return -1;
        }
        p = skip_ws(p, end);
        if (p >= end || *p != '{')
        {
            if (err && errlen) snprintf(err, errlen, "expected object after key %s", key);
            free(buf); return -1;
        }
        const char *close = find_matching_brace(p, end);
        if (!close)
        {
            if (err && errlen) snprintf(err, errlen, "unterminated object for %s", key);
            free(buf); return -1;
        }
        const char *section_start = p + 1;
        const char *section_end = close;
        if (!strcmp(key, "c2"))
            parse_c2(section_start, section_end, cfg);
        if (!strcmp(key, "crypto"))
            parse_crypto(section_start, section_end, cfg);
        if (!strcmp(key, "timing"))
            parse_timing(section_start, section_end, cfg);
        if (!strcmp(key, "network"))
            parse_network(section_start, section_end, cfg);
        if (!strcmp(key, "bof"))
            parse_bof(section_start, section_end, cfg);
        if (!strcmp(key, "backoff"))
            parse_backoff(section_start, section_end, cfg);
        if (!strcmp(key, "server"))
            parse_server(section_start, section_end, cfg);
        p = close + 1;
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }

    free(buf);
    return 0;
}
