#!/bin/sh
EXPORT_MODE=hardcoded_exports exec python3 "$(dirname "$0")/../reference.py" "$@"
