#!/bin/sh
HEURISTIC_SCENARIO=log_blocks exec python3 "$(dirname "$0")/../reference.py" "$@"
