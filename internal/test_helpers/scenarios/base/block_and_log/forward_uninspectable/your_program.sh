#!/bin/sh
POLICY_SCENARIO=forward_uninspectable exec python3 "$(dirname "$0")/../reference.py" "$@"
