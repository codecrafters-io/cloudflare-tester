#!/bin/sh
CLASSIFIER_SCENARIO=keep_partial_scores exec python3 "$(dirname "$0")/../reference.py" "$@"
