#!/bin/sh
MODE=hardcoded_patterns exec python3 "$(dirname "$0")/../reference.py" "$@"
