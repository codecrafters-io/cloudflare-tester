#!/bin/sh
HEURISTIC_SCENARIO=maximum_weight exec python3 "$(dirname "$0")/../reference.py" "$@"
