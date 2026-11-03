#!/bin/sh
THRESHOLD_SCENARIO=strict_high exec python3 "$(dirname "$0")/../reference.py" "$@"
