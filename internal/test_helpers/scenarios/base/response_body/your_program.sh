#!/bin/sh
STAGE1_SCENARIO=response_body exec python3 "$(dirname "$0")/../reference.py" "$@"
