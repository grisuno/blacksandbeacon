# `install.sh`

> Source: [install.sh:1](../../install.sh#L1) | language `sh` | coverage 100.0% | [API index](../index.md)

install.sh - Install build deps and build everything.

Idempotent: safe to run on a fresh checkout. Tested on Debian 12 and Ubuntu 22.04.  For day-to-day development, prefer running `make` directly so errors are reported per-target. This script is for first-time setup and CI parity.
