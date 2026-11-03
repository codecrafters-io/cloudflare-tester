#!/bin/sh
STREAM_MODE=continue_after_error exec python3 "$(dirname "$0")/../reference.py" "$@"
