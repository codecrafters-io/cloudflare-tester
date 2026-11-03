#!/bin/sh
STREAM_MODE=regex_canary exec python3 "$(dirname "$0")/../reference.py" "$@"
