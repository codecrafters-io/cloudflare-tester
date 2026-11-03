#!/bin/sh
TOOL_MODE=scan_empty_batch exec python3 "$(dirname "$0")/../reference.py" "$@"
