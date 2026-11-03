#!/bin/sh
EVASION_SCENARIO=recursive_decode exec python3 "$(dirname "$0")/../reference.py" "$@"
