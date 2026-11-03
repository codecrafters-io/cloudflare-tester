#!/bin/sh
HEURISTIC_SCENARIO=skip_normalization exec python3 "$(dirname "$0")/../reference.py" "$@"
