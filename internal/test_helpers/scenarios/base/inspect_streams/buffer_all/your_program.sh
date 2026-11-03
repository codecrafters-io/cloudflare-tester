#!/bin/sh
STREAM_MODE=buffer_all exec python3 "$(dirname "$0")/../reference.py" "$@"
