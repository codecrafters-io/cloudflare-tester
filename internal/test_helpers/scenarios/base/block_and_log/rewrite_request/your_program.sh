#!/bin/sh
POLICY_SCENARIO=rewrite_request exec python3 "$(dirname "$0")/../reference.py" "$@"
