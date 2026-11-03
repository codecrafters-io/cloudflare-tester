#!/bin/sh
MODE=reuse_values exec python3 "$(dirname "$0")/../reference.py" "$@"
