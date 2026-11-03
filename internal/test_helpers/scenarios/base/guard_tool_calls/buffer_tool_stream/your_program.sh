#!/bin/sh
TOOL_MODE=buffer_tool_stream exec python3 "$(dirname "$0")/../reference.py" "$@"
