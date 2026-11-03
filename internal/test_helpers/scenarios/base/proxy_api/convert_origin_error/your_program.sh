#!/bin/sh
PROXY_SCENARIO=convert_origin_error exec python3 "$(dirname "$0")/../reference.py" "$@"
