#!/bin/sh
STAGE1_SCENARIO=slow_response exec python3 "$(dirname "$0")/../reference.py" "$@"
