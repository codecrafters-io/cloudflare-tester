#!/bin/sh
POLICY_SCENARIO=skip_parts exec python3 "$(dirname "$0")/../reference.py" "$@"
