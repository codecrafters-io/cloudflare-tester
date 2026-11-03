#!/bin/sh
THRESHOLD_SCENARIO=tool_for_all_roles exec python3 "$(dirname "$0")/../reference.py" "$@"
