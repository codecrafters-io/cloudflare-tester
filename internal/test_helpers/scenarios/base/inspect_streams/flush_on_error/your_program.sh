#!/bin/sh
STREAM_MODE=flush_on_error exec python3 "$(dirname "$0")/../reference.py" "$@"
