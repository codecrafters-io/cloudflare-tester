#!/bin/sh
CLASSIFIER_SCENARIO=leak_authorization exec python3 "$(dirname "$0")/../reference.py" "$@"
