#!/bin/sh
POLICY_SCENARIO=join_messages exec python3 "$(dirname "$0")/../reference.py" "$@"
