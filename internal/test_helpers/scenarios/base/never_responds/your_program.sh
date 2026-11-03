#!/bin/sh
STAGE1_SCENARIO=never_responds exec python3 "$(dirname "$0")/../reference.py" "$@"
