#!/bin/sh
POLICY_SCENARIO=invalid_error exec python3 "$(dirname "$0")/../reference.py" "$@"
