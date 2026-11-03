#!/bin/sh
STREAM_MODE=no_json_unescape exec python3 "$(dirname "$0")/../reference.py" "$@"
