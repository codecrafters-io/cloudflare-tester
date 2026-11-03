#!/bin/sh
STREAM_MODE=no_flush exec python3 "$(dirname "$0")/../reference.py" "$@"
