#!/bin/sh
TOOL_MODE=substring_host exec python3 "$(dirname "$0")/../reference.py" "$@"
