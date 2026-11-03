#!/bin/sh
CLASSIFIER_SCENARIO=hardcoded_threshold exec python3 "$(dirname "$0")/../reference.py" "$@"
