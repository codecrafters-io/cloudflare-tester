#!/bin/sh
MODE=leak_extra_field exec python3 "$(dirname "$0")/../reference.py" "$@"
