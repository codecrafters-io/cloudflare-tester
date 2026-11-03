#!/bin/sh
HEURISTIC_SCENARIO=hardcoded_policy exec python3 "$(dirname "$0")/../reference.py" "$@"
