#!/bin/sh
EXPORT_MODE=all_results_private exec python3 "$(dirname "$0")/../reference.py" "$@"
