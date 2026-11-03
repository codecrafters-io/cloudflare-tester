#!/bin/sh
HEURISTIC_SCENARIO=join_texts exec python3 "$(dirname "$0")/../reference.py" "$@"
