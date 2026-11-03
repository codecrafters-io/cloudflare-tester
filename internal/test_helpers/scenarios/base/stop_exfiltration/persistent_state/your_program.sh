#!/bin/sh
EXPORT_MODE=persistent_state exec python3 "$(dirname "$0")/../reference.py" "$@"
