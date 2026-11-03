#!/bin/sh
EVASION_SCENARIO=skip_nfkc exec python3 "$(dirname "$0")/../reference.py" "$@"
