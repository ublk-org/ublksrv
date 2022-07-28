# SPDX-License-Identifier: MIT or GPL-2.0-only
#!/bin/bash

DIR=$(cd "$(dirname "$0")";pwd)

#. $DIR/common/fio_common

export UBLK=${DIR}/../ublk
export TEST_DIR=$DIR
export UBLK_TMP_DIR=$DIR/tmp
export UBLK_TMP=`mktemp /tmp/ublk_tmp_XXXXX`

[ ! -d ${UBLK_TMP_DIR} ] && mkdir ${UBLK_TMP_DIR}

run_test() {
	TS=$1

	NAME=`basename $TS`
	TMP=`dirname $TS`
	GRP=`basename $TMP`

	echo "running $GRP/$NAME"
	sh -c $TS 
}


TEST=$1
export TRUNTIME=$2
export T_URING_COMP=0
export T_NEED_GET_DATA=0

if [ -d $TEST ]; then
		for ITEM in `ls ${TEST} | grep -v "~$"`; do
				run_test $TEST/$ITEM
		done
elif [ -f $TEST ]; then
		run_test $TEST
fi

rm -f ${UBLK_TMP}
