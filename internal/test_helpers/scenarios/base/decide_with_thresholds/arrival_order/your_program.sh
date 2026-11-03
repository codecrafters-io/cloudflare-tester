#!/bin/sh
THRESHOLD_SCENARIO=arrival_order exec python3 "$(dirname "$0")/../reference.py" "$@"
