#!/bin/sh
POLICY_SCENARIO=raw_match exec python3 "$(dirname "$0")/../reference.py" "$@"
