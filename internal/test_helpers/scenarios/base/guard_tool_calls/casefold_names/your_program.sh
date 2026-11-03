#!/bin/sh
TOOL_MODE=casefold_names exec python3 "$(dirname "$0")/../reference.py" "$@"
