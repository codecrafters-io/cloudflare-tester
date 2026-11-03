#!/bin/sh
EVASION_SCENARIO=lower_only exec python3 "$(dirname "$0")/../reference.py" "$@"
