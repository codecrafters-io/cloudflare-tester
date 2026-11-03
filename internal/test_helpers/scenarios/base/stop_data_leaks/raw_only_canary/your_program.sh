#!/bin/sh
MODE=raw_only_canary exec python3 "$(dirname "$0")/../reference.py" "$@"
