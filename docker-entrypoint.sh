#!/bin/sh
set -e

# Allow config via env vars
CENTRAL_ADDR="${CENTRAL_ADDR:-central:38472}"
DATA_LISTEN="${DATA_LISTEN:-0.0.0.0:443}"

exec mscope-edge \
  -central-addr "$CENTRAL_ADDR" \
  -data-listen "$DATA_LISTEN"
