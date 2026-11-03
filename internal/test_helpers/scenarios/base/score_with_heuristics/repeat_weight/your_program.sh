#!/bin/sh
HEURISTIC_SCENARIO=repeat_weight exec python3 "$(dirname "$0")/../reference.py" "$@"
