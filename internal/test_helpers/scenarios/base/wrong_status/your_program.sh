#!/bin/sh
STAGE1_SCENARIO=wrong_status exec python3 "$(dirname "$0")/../reference.py" "$@"
