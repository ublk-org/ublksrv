#!/bin/bash

DIR=$(cd "$(dirname "$0")";pwd)

#. $DIR/common/fio_common

export UBD=${DIR}/../ubd
export TEST_DIR=$DIR
export UBD_TMP=`mktemp /tmp/ubd_tmp_XXXXX`

TEST=$1

if [ -d $TEST ]; then
		for ITEM in `ls ${TEST}`; do
				. $TEST/$ITEM
		done
elif [ -f $TEST ]; then
	sh -c $TEST 
fi

rm -f ${UBD_TMP}
