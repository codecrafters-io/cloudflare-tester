#!/bin/sh
EXPORT_MODE=literal_only exec python3 "$(dirname "$0")/../reference.py" "$@"
