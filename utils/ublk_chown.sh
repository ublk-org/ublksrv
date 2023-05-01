#!/bin/bash
# SPDX-License-Identifier: MIT or GPL-2.0-only

MY_DIR=$(cd "$(dirname "$0")";pwd)
ID=`${MY_DIR}/ublk_user_id $1`

if [ "$2" == "add" ]; then
	if [ "${ID}" != "-1:-1" ]; then
		/usr/bin/chown $ID /dev/$1 > /dev/null 2>&1
	fi
fi
