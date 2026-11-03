#!/bin/sh
TOOL_MODE=last_fragment_only exec python3 "$(dirname "$0")/../reference.py" "$@"
