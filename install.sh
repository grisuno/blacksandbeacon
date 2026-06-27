#!/bin/bash
#
# install.sh - Install build deps and build everything.
#
# Idempotent: safe to run on a fresh checkout.
# Tested on Debian 12 and Ubuntu 22.04.
#
# For day-to-day development, prefer running `make` directly so
# errors are reported per-target. This script is for first-time
# setup and CI parity.

set -e

if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
        libcurl4-openssl-dev \
        libssl-dev \
        python3 \
        python3-pip \
        python3-venv \
        make
else
    echo "install.sh: apt-get not found."
    echo "Install these packages manually: gcc libcurl libssl python3 make"
    echo "Then run: make beacon bofs"
    exit 1
fi

# Build the canonical beacon and all sample BOFs.
make beacon
make bofs
