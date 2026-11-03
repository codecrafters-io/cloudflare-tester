#!/bin/sh
CLASSIFIER_SCENARIO=sequential exec python3 "$(dirname "$0")/../reference.py" "$@"
