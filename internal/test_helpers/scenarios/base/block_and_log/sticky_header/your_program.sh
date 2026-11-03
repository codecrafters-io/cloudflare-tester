#!/bin/sh
POLICY_SCENARIO=sticky_header exec python3 "$(dirname "$0")/../reference.py" "$@"
