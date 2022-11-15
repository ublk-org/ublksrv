#!/bin/bash
# SPDX-License-Identifier: MIT or GPL-2.0-only

MY_DIR=$(cd "$(dirname "$0")";pwd)
ID=`${MY_DIR}/ublk_user_id $1`
/usr/bin/chown $ID /dev/$1
