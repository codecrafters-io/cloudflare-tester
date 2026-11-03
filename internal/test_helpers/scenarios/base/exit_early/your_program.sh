#!/bin/sh
STAGE1_SCENARIO=exit_early exec python3 "$(dirname "$0")/../reference.py" "$@"
