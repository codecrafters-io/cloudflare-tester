#!/bin/sh
MODE=skip_output exec python3 "$(dirname "$0")/../reference.py" "$@"
