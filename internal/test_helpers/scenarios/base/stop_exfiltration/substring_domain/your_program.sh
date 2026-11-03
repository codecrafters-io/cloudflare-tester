#!/bin/sh
EXPORT_MODE=substring_domain exec python3 "$(dirname "$0")/../reference.py" "$@"
