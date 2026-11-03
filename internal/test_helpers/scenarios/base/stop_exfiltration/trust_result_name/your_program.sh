#!/bin/sh
EXPORT_MODE=trust_result_name exec python3 "$(dirname "$0")/../reference.py" "$@"
