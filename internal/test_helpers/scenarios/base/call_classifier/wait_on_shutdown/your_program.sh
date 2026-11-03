#!/bin/sh
CLASSIFIER_SCENARIO=wait_on_shutdown exec python3 "$(dirname "$0")/../reference.py" "$@"
