#!/bin/sh
HEURISTIC_SCENARIO=near_bytes exec python3 "$(dirname "$0")/../reference.py" "$@"
