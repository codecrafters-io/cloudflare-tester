#!/bin/sh
EVASION_SCENARIO=skip_zero_width exec python3 "$(dirname "$0")/../reference.py" "$@"
