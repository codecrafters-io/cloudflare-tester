#!/bin/sh
PROXY_SCENARIO=stage1_only exec python3 "$(dirname "$0")/../reference.py" "$@"
