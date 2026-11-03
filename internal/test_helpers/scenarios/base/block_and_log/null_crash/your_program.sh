#!/bin/sh
POLICY_SCENARIO=null_crash exec python3 "$(dirname "$0")/../reference.py" "$@"
