#!/bin/sh
POLICY_SCENARIO=user_only exec python3 "$(dirname "$0")/../reference.py" "$@"
