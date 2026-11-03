#!/bin/sh
CLASSIFIER_SCENARIO=normalize_detector_input exec python3 "$(dirname "$0")/../reference.py" "$@"
