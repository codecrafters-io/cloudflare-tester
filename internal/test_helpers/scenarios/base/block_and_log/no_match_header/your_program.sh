#!/bin/sh
POLICY_SCENARIO=no_match_header exec python3 "$(dirname "$0")/../reference.py" "$@"
