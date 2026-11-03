#!/bin/sh
CLASSIFIER_SCENARIO=drop_role exec python3 "$(dirname "$0")/../reference.py" "$@"
