#!/bin/sh
HEURISTIC_SCENARIO=near_first_only exec python3 "$(dirname "$0")/../reference.py" "$@"
