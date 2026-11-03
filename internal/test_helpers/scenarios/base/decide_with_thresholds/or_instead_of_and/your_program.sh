#!/bin/sh
THRESHOLD_SCENARIO=or_instead_of_and exec python3 "$(dirname "$0")/../reference.py" "$@"
