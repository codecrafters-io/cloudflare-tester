#!/bin/sh
STREAM_MODE=event_only exec python3 "$(dirname "$0")/../reference.py" "$@"
