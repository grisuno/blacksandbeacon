#
# Makefile for Black Sand Beacon
#
# Targets:
#   make beacon       - build the v1 beacon (default canonical)
#   make beacon-v1    - build beacons/v1/beacon.c
#   make beacon-v2    - build beacons/v2/beacon.c (mesh variant)
#   make beacon-v3    - build beacons/v3/beacon.c
#   make all-beacons  - build all three variants
#   make bofs         - build all BOF .x64.o files
#   make bof-<name>   - build a single BOF (e.g. make bof-whoami)
#   make c2           - install Python deps for the C2 server
#   make test         - run the test suite
#   make config       - copy config.example.json -> config.json
#   make clean        - remove build artifacts
#   make distclean    - also remove config.json and generated objects
#
# All build artifacts are placed under build/ so the source tree
# stays clean. The compiled beacons and BOFs are written to
# build/beacon, build/beacon-v2, build/bof/<name>.x64.o
#
# The Makefile does NOT run apt-get install. If libssl-dev or
# libcurl4-openssl-dev is missing, the build will fail with a
# clear error pointing at the missing header.

CC          ?= gcc
CFLAGS      ?= -Wall -Wextra -O2 -g
BOF_CFLAGS  ?= -fPIC -nostdlib -m64 -O2 -Wall -Wextra
LDFLAGS     ?= -rdynamic -lcurl -lssl -lcrypto

BUILD_DIR   = build
BOF_OUT     = $(BUILD_DIR)/bof
CONFIG      = config/config.json
CONFIG_EX   = config/config.example.json

COMMON_SRC = include/config.c include/aes.c include/aes_cfb.c include/cJSON.c include/beacon_common.c
COMMON_HDR  = -I include

# --- header probe ---
# A real `make beacon` build needs OpenSSL and libcurl headers.
# We probe at parse time and expose the result as a Make variable
# so the recipe for each beacon target can call `require-dev-headers`
# and fail with an actionable message instead of a wall of
# "fatal error: openssl/buffer.h".
HAS_OPENSSL := $(shell echo '#include <openssl/buffer.h>' | $(CC) -E - >/dev/null 2>&1 && echo yes || echo no)
HAS_CURL    := $(shell echo '#include <curl/curl.h>'     | $(CC) -E - >/dev/null 2>&1 && echo yes || echo no)

define require-dev-headers
@if [ "$(HAS_OPENSSL)" != "yes" ] || [ "$(HAS_CURL)" != "yes" ]; then \
    echo "ERROR: missing development headers required to build the beacon."; \
    echo ""; \
    echo "  OpenSSL headers: $(HAS_OPENSSL)"; \
    echo "  libcurl headers: $(HAS_CURL)"; \
    echo ""; \
    echo "Install them with one of:"; \
    echo "  Debian/Ubuntu : sudo apt-get install libssl-dev libcurl4-openssl-dev"; \
    echo "  Fedora/RHEL   : sudo dnf install openssl-devel libcurl-devel"; \
    echo "  Arch          : sudo pacman -S openssl libcurl-gnutls"; \
    echo ""; \
    echo "If you do not need the beacon binary right now, the BOFs and the"; \
    echo "C2 server do not need these headers - run: make bofs c2 test"; \
    exit 1; \
fi
endef

BEACON_V1   = $(BUILD_DIR)/beacon-v1
BEACON_V2   = $(BUILD_DIR)/beacon-v2
BEACON_V3   = $(BUILD_DIR)/beacon-v3

BOFS        = whoami is_sudo cat userenum suid_enum
BOF_OBJS    = $(addprefix $(BOF_OUT)/,$(addsuffix .x64.o,$(BOFS)))

.PHONY: all help beacon beacon-v1 beacon-v2 beacon-v3 all-beacons bofs \
        bof-whoami bof-is_sudo bof-cat bof-userenum bof-suid_enum c2 test config \
        install install-beacon install-bofs uninstall \
        clean distclean

all: $(BUILD_DIR)/beacon all-beacons bofs

help:
	@echo "Black Sand Beacon - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make beacon       - build v1 beacon (default)"
	@echo "  make beacon-v1    - build beacons/v1/beacon.c"
	@echo "  make beacon-v2    - build beacons/v2/beacon.c"
	@echo "  make beacon-v3    - build beacons/v3/beacon.c"
	@echo "  make all-beacons  - build all three"
	@echo "  make bofs         - build all BOF .x64.o"
	@echo "  make bof-<name>   - build one BOF (whoami|is_sudo|cat|userenum|suid_enum)"
	@echo "  make c2           - install Python deps for c2/server.py"
	@echo "  make test         - run the test suite"
	@echo "  make config       - copy config.example.json to config.json"
	@echo "  make install      - optional: stage deploy tree into DESTDIR (default ./deploy)"
	@echo "  make install-all  - same + copy BOFs"
	@echo "  make uninstall    - remove the deploy tree"
	@echo "  make clean        - remove build/"
	@echo "  make distclean    - clean + remove config.json"
	@echo ""
	@echo "Set BSB_CONFIG to override the config path (default: $(CONFIG))"

# --- config ---
config: $(CONFIG)

$(CONFIG): $(CONFIG_EX)
	@cp $(CONFIG_EX) $(CONFIG)
	@echo "[*] Wrote $(CONFIG) from example."
	@echo "[*] Edit it to set your AES key and C2 URL before running the beacon."

# --- beacons ---
beacon: $(BUILD_DIR)/beacon
	@echo ""
	@echo "ready. run:"
	@echo "  ./build/beacon"
	@echo ""
	@echo "the binary picks up build/config.json (next to itself)"
	@echo "or any of the standard search paths. no env vars needed."

beacon-v1: $(BEACON_V1)

$(BEACON_V1): beacons/v1/beacon.c $(COMMON_SRC) include/config.h include/aes.h include/cJSON.h | $(BUILD_DIR)
	$(require-dev-headers)
	$(CC) $(CFLAGS) $(COMMON_HDR) -I beacons/v1 -o $@ $< $(COMMON_SRC) $(LDFLAGS)

# build/beacon is the canonical "just run me" artifact. It is a
# copy of beacon-v1 placed next to a staged config.json so the
# search order resolves without any env vars.
$(BUILD_DIR)/beacon: $(BEACON_V1) | $(CONFIG)
	install -m 0755 $(BEACON_V1) $@
	@if [ ! -e $(BUILD_DIR)/config.json ]; then \
	    install -m 0600 $(CONFIG) $(BUILD_DIR)/config.json; \
	    echo "[stage] $(BUILD_DIR)/config.json"; \
	fi
	@echo "[stage] $@"
	@# convenience symlink for users who want the explicit version
	@ln -sf beacon $(BUILD_DIR)/beacon-v1 2>/dev/null || true

beacon-v2: $(BEACON_V2)

$(BEACON_V2): beacons/v2/beacon.c $(COMMON_SRC) include/config.h include/aes.h include/cJSON.h | $(BUILD_DIR)
	$(require-dev-headers)
	$(CC) $(CFLAGS) $(COMMON_HDR) -I beacons/v2 -o $@ $< $(COMMON_SRC) $(LDFLAGS)

beacon-v3: $(BEACON_V3)

$(BEACON_V3): beacons/v3/beacon.c $(COMMON_SRC) include/config.h include/aes.h include/cJSON.h | $(BUILD_DIR)
	$(require-dev-headers)
	$(CC) $(CFLAGS) $(COMMON_HDR) -I beacons/v3 -o $@ $< $(COMMON_SRC) $(LDFLAGS)

all-beacons: $(BEACON_V1) $(BEACON_V2) $(BEACON_V3)

# --- BOFs ---
bofs: $(BOF_OBJS)
	@echo ""
	@echo "BOFs ready in $(BOF_OUT)/"
	@echo "copy them to your C2's sessions/uploads/ dir:"
	@echo "  cp $(BOF_OUT)/*.x64.o /path/to/c2/sessions/uploads/"

bof-whoami: $(BOF_OUT)/whoami.x64.o
bof-is_sudo: $(BOF_OUT)/is_sudo.x64.o
bof-cat: $(BOF_OUT)/cat.x64.o
bof-userenum: $(BOF_OUT)/userenum.x64.o
bof-suid_enum: $(BOF_OUT)/suid_enum.x64.o

$(BOF_OUT)/%.x64.o: bof/%/bof.c bof/include/beacon_api.h bof/include/syscalls.h | $(BOF_OUT)
	$(CC) -c $(BOF_CFLAGS) -I bof/include -o $@ $<

# --- C2 server ---
c2:
	@echo "[*] Installing Python deps for c2/server.py"
	@command -v pip3 >/dev/null || { echo "pip3 not found"; exit 1; }
	pip3 install -r requirements.txt

# --- tests ---
test: $(BUILD_DIR)/config_harness
	@python3 tests/test_config.py
	@python3 tests/test_crypto.py
	@python3 tests/test_bof_compile.py
	@python3 tests/test_beacon_build.py
	@python3 tests/test_c2_server.py
	@python3 tests/test_c2_http_e2e.py
	@python3 tests/test_install_deploy.py

$(BUILD_DIR)/config_harness: tests/config_harness.c include/config.c include/config.h | $(BUILD_DIR)
	$(CC) -std=c11 -Wall -Wextra -O0 -g $(COMMON_HDR) -o $@ tests/config_harness.c include/config.c

# --- housekeeping ---
$(BUILD_DIR) $(BOF_OUT):
	@mkdir -p $@

# --- deploy (optional) ---
# Stage a self-contained deploy tree for shipping to a target host.
# This is NOT the normal flow; the normal flow is just
# `make beacon` and run ./build/beacon. Use this only when you
# need to bundle the binary + config + BOFs into a directory you
# can scp/rsync somewhere.
#
#   make install DESTDIR=/tmp/deploy         (beacon + config)
#   make install-all DESTDIR=/tmp/deploy     (also copies BOFs)
#
# The deployed binary finds its config via the same binary-
# relative search path as build/beacon, so the staged dir is
# drop-in runnable from any host.
DESTDIR      ?= deploy
BSB_PREFIX   ?= beacon
INSTALL_DIR   = $(DESTDIR)
INSTALL_BIN   = $(INSTALL_DIR)/$(BSB_PREFIX)
INSTALL_CFG   = $(INSTALL_DIR)/config.json
INSTALL_BOF   = $(INSTALL_DIR)/bof
INSTALL_BEACONS = $(BEACON_V1) $(BEACON_V2) $(BEACON_V3)

install: install-beacon install-config
	@echo "deploy staged at: $(INSTALL_DIR)"
	@echo "scp it:           scp -r $(INSTALL_DIR)/* user@host:dest/"

install-beacon: all-beacons
	@mkdir -p $(INSTALL_DIR)
	install -m 0755 $(BEACON_V1) $(INSTALL_BIN)
	install -m 0755 $(BEACON_V2) $(INSTALL_DIR)/beacon-v2
	@if [ -f $(BEACON_V3) ]; then install -m 0755 $(BEACON_V3) $(INSTALL_DIR)/beacon-v3; fi
	@ln -sf beacon $(INSTALL_DIR)/beacon-v1 2>/dev/null || true

install-config: $(CONFIG)
	@mkdir -p $(INSTALL_DIR)
	install -m 0600 $(CONFIG) $(INSTALL_CFG)

install-bofs: bofs
	@mkdir -p $(INSTALL_BOF)
	install -m 0644 $(BOF_OBJS) $(INSTALL_BOF)/

install-all: install install-bofs

uninstall:
	rm -rf $(INSTALL_DIR)

clean:
	rm -rf $(BUILD_DIR)

distclean: clean
	rm -f $(CONFIG)
