#!/bin/sh
THRESHOLD_SCENARIO=keep_classifier_cutoff exec python3 "$(dirname "$0")/../reference.py" "$@"
