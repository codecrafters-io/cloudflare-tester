#!/bin/sh
EXPORT_MODE=first_call_only exec python3 "$(dirname "$0")/../reference.py" "$@"
