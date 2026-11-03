#!/bin/sh
TOOL_MODE=hardcoded_policy exec python3 "$(dirname "$0")/../reference.py" "$@"
