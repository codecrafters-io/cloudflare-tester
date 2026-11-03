#!/bin/sh
HEURISTIC_SCENARIO=duplicate_signal exec python3 "$(dirname "$0")/../reference.py" "$@"
