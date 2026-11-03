#!/bin/sh
HEURISTIC_SCENARIO=previous_stage exec python3 "$(dirname "$0")/../reference.py" "$@"
