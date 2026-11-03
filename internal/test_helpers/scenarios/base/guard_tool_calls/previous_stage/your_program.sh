#!/bin/sh
exec python3 "$(dirname "$0")/../../inspect_streams/reference.py" "$@"
