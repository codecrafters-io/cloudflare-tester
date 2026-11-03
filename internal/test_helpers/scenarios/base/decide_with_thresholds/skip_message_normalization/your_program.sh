#!/bin/sh
THRESHOLD_SCENARIO=skip_message_normalization exec python3 "$(dirname "$0")/../reference.py" "$@"
