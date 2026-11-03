#!/bin/sh
THRESHOLD_SCENARIO=ignore_tool_role exec python3 "$(dirname "$0")/../reference.py" "$@"
