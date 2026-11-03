#!/bin/sh
THRESHOLD_SCENARIO=strict_heuristic_medium exec python3 "$(dirname "$0")/../reference.py" "$@"
