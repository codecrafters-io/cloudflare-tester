#!/bin/sh
POLICY_SCENARIO=rewrite_response exec python3 "$(dirname "$0")/../reference.py" "$@"
