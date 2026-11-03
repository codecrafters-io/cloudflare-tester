#!/bin/sh
THRESHOLD_SCENARIO=request_wide_heuristics exec python3 "$(dirname "$0")/../reference.py" "$@"
