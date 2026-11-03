#!/bin/sh
EXPORT_MODE=leak_nonstream_error exec python3 "$(dirname "$0")/../reference.py" "$@"
