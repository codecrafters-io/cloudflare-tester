#!/bin/sh
STREAM_MODE=duplicate_error exec python3 "$(dirname "$0")/../reference.py" "$@"
