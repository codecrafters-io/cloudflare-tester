#!/bin/sh
PROXY_SCENARIO=wrong_host exec python3 "$(dirname "$0")/../reference.py" "$@"
