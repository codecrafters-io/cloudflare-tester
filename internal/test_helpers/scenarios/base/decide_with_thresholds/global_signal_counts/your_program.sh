#!/bin/sh
THRESHOLD_SCENARIO=global_signal_counts exec python3 "$(dirname "$0")/../reference.py" "$@"
