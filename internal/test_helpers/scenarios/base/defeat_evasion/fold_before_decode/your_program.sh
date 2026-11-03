#!/bin/sh
EVASION_SCENARIO=fold_before_decode exec python3 "$(dirname "$0")/../reference.py" "$@"
