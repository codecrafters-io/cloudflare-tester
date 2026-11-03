#!/bin/sh
CLASSIFIER_SCENARIO=always_open exec python3 "$(dirname "$0")/../reference.py" "$@"
