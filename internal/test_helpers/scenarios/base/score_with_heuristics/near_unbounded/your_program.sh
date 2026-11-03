#!/bin/sh
HEURISTIC_SCENARIO=near_unbounded exec python3 "$(dirname "$0")/../reference.py" "$@"
