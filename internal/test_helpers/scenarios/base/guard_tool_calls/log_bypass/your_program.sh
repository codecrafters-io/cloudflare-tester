#!/bin/sh
TOOL_MODE=log_bypass exec python3 "$(dirname "$0")/../reference.py" "$@"
