#!/bin/sh
THRESHOLD_SCENARIO=fallback_ignores_heuristics exec python3 "$(dirname "$0")/../reference.py" "$@"
