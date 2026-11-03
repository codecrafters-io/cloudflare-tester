#!/bin/sh
TOOL_MODE=stream_non_atomic exec python3 "$(dirname "$0")/../reference.py" "$@"
