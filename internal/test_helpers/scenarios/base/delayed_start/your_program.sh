#!/bin/sh
STAGE1_SCENARIO=delayed_start exec python3 "$(dirname "$0")/../reference.py" "$@"
