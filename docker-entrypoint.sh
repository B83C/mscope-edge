#!/bin/sh
set -e

CENTRAL_ADDR="${CENTRAL_ADDR:-central:38472}"

exec mscope-edge \
  -central-addr "$CENTRAL_ADDR"
