#!/bin/sh
EXPORT_MODE=whole_record_only exec python3 "$(dirname "$0")/../reference.py" "$@"
