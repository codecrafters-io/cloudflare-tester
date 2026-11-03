#!/bin/sh
EXPORT_MODE=skip_nonstream exec python3 "$(dirname "$0")/../reference.py" "$@"
