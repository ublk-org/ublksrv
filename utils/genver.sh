#!/bin/sh
# SPDX-License-Identifier: MIT or GPL-2.0-only

GITDESC=$(git describe --dirty|sed -e 's/^v//' 2>/dev/null)

if [ -z "$GITDESC" ]; then
    # Fallback to VERSION file if available
    if [ -f "$(dirname "$0")/../VERSION" ]; then
        GITDESC=$(cat "$(dirname "$0")/../VERSION")
    else
        GITDESC="0.unknown"
    fi
fi

echo $GITDESC

