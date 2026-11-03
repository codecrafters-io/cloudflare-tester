#!/bin/sh
TOOL_MODE=skip_tools exec python3 "$(dirname "$0")/../reference.py" "$@"
