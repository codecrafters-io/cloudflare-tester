#!/bin/sh
PROXY_SCENARIO=change_response exec python3 "$(dirname "$0")/../reference.py" "$@"
