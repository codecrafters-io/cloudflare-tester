#!/bin/sh
MODE=log_allows_canary exec python3 "$(dirname "$0")/../reference.py" "$@"
