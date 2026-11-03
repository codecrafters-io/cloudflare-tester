#!/bin/sh
TOOL_MODE=skip_tool_canary exec python3 "$(dirname "$0")/../reference.py" "$@"
