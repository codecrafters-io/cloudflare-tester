#!/bin/sh
CLASSIFIER_SCENARIO=no_timeout exec python3 "$(dirname "$0")/../reference.py" "$@"
