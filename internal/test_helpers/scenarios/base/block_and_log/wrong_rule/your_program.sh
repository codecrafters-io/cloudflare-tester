#!/bin/sh
POLICY_SCENARIO=wrong_rule exec python3 "$(dirname "$0")/../reference.py" "$@"
