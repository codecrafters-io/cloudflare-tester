#!/bin/sh
THRESHOLD_SCENARIO=classifier_max exec python3 "$(dirname "$0")/../reference.py" "$@"
