#!/bin/sh
EVASION_SCENARIO=skip_base64 exec python3 "$(dirname "$0")/../reference.py" "$@"
