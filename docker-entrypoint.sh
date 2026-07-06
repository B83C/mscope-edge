#!/bin/sh
set -e

if [ $# -eq 0 ]; then
    exec mscope-edge -central-addr "${CENTRAL_ADDR:-central:38472}"
fi
exec mscope-edge "$@"
