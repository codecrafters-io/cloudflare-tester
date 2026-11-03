#!/bin/sh
POLICY_SCENARIO=lower_case exec python3 "$(dirname "$0")/../reference.py" "$@"
