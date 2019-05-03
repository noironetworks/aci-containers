#!/bin/bash

set -euo pipefail

if command -v git &>/dev/null && git rev-parse &>/dev/null; then
    GIT_COMMIT=$(git rev-parse HEAD)
    echo $GIT_COMMIT
    exit 0
fi
echo >&2 'error: unable to determine the git revision'
exit 1
