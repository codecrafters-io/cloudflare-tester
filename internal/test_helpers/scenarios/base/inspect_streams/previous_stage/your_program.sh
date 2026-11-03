#!/bin/sh
exec python3 "$(dirname "$0")/../../stop_data_leaks/reference.py" "$@"
