#!/bin/sh
STAGE1_SCENARIO=redirect exec python3 "$(dirname "$0")/../reference.py" "$@"
