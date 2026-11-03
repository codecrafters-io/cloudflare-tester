#!/bin/sh
MODE=skip_redaction exec python3 "$(dirname "$0")/../reference.py" "$@"
