#!/bin/sh
PROXY_SCENARIO=change_request exec python3 "$(dirname "$0")/../reference.py" "$@"
