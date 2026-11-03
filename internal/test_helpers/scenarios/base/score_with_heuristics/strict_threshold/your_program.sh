#!/bin/sh
HEURISTIC_SCENARIO=strict_threshold exec python3 "$(dirname "$0")/../reference.py" "$@"
