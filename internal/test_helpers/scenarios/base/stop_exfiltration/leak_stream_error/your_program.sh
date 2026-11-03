#!/bin/sh
EXPORT_MODE=leak_stream_error exec python3 "$(dirname "$0")/../reference.py" "$@"
