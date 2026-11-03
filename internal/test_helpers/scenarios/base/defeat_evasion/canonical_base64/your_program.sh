#!/bin/sh
EVASION_SCENARIO=canonical_base64 exec python3 "$(dirname "$0")/../reference.py" "$@"
