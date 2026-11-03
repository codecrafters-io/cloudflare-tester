#!/bin/sh
TOOL_MODE=wrong_url_field exec python3 "$(dirname "$0")/../reference.py" "$@"
