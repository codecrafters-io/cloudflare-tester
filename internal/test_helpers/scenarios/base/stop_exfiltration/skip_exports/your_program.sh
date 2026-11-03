#!/bin/sh
EXPORT_MODE=skip_exports exec python3 "$(dirname "$0")/../reference.py" "$@"
