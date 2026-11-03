#!/bin/sh
POLICY_SCENARIO=wrong_status exec python3 "$(dirname "$0")/../reference.py" "$@"
