#!/bin/sh
STREAM_MODE=no_hold exec python3 "$(dirname "$0")/../reference.py" "$@"
