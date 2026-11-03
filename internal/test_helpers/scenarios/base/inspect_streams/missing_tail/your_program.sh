#!/bin/sh
STREAM_MODE=missing_tail exec python3 "$(dirname "$0")/../reference.py" "$@"
