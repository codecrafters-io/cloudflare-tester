#!/bin/sh
THRESHOLD_SCENARIO=hardcoded_thresholds exec python3 "$(dirname "$0")/../reference.py" "$@"
