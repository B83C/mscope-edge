#!/bin/sh
set -e

exec /usr/bin/mscope-edge -worker-url "${WORKER_URL:-http://localhost:8777}" "$@"
