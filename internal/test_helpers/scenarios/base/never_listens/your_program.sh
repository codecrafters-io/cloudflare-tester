#!/bin/sh
STAGE1_SCENARIO=never_listens exec python3 "$(dirname "$0")/../reference.py" "$@"
