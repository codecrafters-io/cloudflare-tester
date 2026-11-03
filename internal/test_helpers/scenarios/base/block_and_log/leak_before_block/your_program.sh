#!/bin/sh
POLICY_SCENARIO=leak_before_block exec python3 "$(dirname "$0")/../reference.py" "$@"
