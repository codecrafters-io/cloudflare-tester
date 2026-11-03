#!/bin/sh
HEURISTIC_SCENARIO=any_signal_blocks exec python3 "$(dirname "$0")/../reference.py" "$@"
