#!/bin/sh
PROXY_SCENARIO=extra_response exec python3 "$(dirname "$0")/../reference.py" "$@"
