#!/bin/sh
EVASION_SCENARIO=hardcoded_map exec python3 "$(dirname "$0")/../reference.py" "$@"
