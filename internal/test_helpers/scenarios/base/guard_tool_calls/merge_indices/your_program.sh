#!/bin/sh
TOOL_MODE=merge_indices exec python3 "$(dirname "$0")/../reference.py" "$@"
