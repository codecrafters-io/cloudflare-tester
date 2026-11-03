#!/bin/sh
STREAM_MODE=byte_hold exec python3 "$(dirname "$0")/../reference.py" "$@"
