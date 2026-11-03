#!/bin/sh
EVASION_SCENARIO=skip_homoglyphs exec python3 "$(dirname "$0")/../reference.py" "$@"
