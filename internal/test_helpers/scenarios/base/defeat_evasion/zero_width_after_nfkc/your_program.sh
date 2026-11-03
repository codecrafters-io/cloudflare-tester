#!/bin/sh
EVASION_SCENARIO=zero_width_after_nfkc exec python3 "$(dirname "$0")/../reference.py" "$@"
