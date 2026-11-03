#!/bin/sh
CLASSIFIER_SCENARIO=first_message_only exec python3 "$(dirname "$0")/../reference.py" "$@"
