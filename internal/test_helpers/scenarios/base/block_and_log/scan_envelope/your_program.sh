#!/bin/sh
POLICY_SCENARIO=scan_envelope exec python3 "$(dirname "$0")/../reference.py" "$@"
