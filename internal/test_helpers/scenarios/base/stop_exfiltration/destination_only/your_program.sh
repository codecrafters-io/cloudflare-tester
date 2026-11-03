#!/bin/sh
EXPORT_MODE=destination_only exec python3 "$(dirname "$0")/../reference.py" "$@"
