#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

GITDESC=$(git describe --dirty|sed -e 's/^v//' 2>/dev/null)

if [ -z "$GITDESC" ]; then
    GITDESC="0.unknown"
fi

echo $GITDESC

