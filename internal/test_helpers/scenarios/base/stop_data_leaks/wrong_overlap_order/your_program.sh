#!/bin/sh
MODE=wrong_overlap_order exec python3 "$(dirname "$0")/../reference.py" "$@"
