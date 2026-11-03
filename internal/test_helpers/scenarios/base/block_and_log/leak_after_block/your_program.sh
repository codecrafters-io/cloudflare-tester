#!/bin/sh
POLICY_SCENARIO=leak_after_block exec python3 "$(dirname "$0")/../reference.py" "$@"
