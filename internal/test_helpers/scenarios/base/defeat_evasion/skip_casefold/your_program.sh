#!/bin/sh
EVASION_SCENARIO=skip_casefold exec python3 "$(dirname "$0")/../reference.py" "$@"
