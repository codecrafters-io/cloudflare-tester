#!/bin/sh
TOOL_MODE=drop_stream_tools exec python3 "$(dirname "$0")/../reference.py" "$@"
