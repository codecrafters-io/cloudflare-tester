#!/bin/sh
STAGE1_SCENARIO=one_request exec python3 "$(dirname "$0")/../reference.py" "$@"
