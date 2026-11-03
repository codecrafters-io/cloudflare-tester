#!/bin/sh
PROXY_SCENARIO=drop_authorization exec python3 "$(dirname "$0")/../reference.py" "$@"
