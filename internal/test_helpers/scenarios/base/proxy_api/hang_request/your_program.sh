#!/bin/sh
PROXY_SCENARIO=hang_request exec python3 "$(dirname "$0")/../reference.py" "$@"
