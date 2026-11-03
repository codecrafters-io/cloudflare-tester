#!/bin/sh
EXPORT_MODE=skip_query_values exec python3 "$(dirname "$0")/../reference.py" "$@"
