#!/bin/sh
POLICY_SCENARIO=pass_all exec python3 "$(dirname "$0")/../reference.py" "$@"
