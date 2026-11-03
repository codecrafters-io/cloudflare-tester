#!/bin/sh
PROXY_SCENARIO=extra_success_response exec python3 "$(dirname "$0")/../reference.py" "$@"
