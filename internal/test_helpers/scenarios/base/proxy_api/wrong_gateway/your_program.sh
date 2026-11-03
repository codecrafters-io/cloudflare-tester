#!/bin/sh
PROXY_SCENARIO=wrong_gateway exec python3 "$(dirname "$0")/../reference.py" "$@"
