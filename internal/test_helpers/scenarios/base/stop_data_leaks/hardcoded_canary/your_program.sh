#!/bin/sh
MODE=hardcoded_canary exec python3 "$(dirname "$0")/../reference.py" "$@"
