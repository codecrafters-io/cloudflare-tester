#!/bin/sh
MODE=strings_only exec python3 "$(dirname "$0")/../reference.py" "$@"
