#!/bin/sh
EVASION_SCENARIO=skip_decoded_normalization exec python3 "$(dirname "$0")/../reference.py" "$@"
