#!/bin/sh
TOOL_MODE=malformed_allowed exec python3 "$(dirname "$0")/../reference.py" "$@"
