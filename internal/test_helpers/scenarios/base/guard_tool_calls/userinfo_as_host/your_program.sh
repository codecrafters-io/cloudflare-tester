#!/bin/sh
TOOL_MODE=userinfo_as_host exec python3 "$(dirname "$0")/../reference.py" "$@"
