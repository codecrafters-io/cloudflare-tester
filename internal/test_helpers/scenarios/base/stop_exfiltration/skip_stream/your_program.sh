#!/bin/sh
EXPORT_MODE=skip_stream exec python3 "$(dirname "$0")/../reference.py" "$@"
