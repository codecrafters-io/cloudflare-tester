#!/bin/sh
MODE=per_message_map exec python3 "$(dirname "$0")/../reference.py" "$@"
