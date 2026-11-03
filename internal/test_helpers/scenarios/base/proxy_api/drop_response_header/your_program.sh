#!/bin/sh
PROXY_SCENARIO=drop_response_header exec python3 "$(dirname "$0")/../reference.py" "$@"
