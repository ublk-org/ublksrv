#!/bin/bash

DIR=$(cd "$(dirname "$0")";pwd)

#. $DIR/common/fio_common

export UBD=${DIR}/../ubd
export TEST_DIR=$DIR
export UBD_TMP=`mktemp /tmp/ubd_tmp_XXXXX`

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

if [ -d $TEST ]; then
		for ITEM in `ls ${TEST}`; do
				run_test $TEST/$ITEM
		done
elif [ -f $TEST ]; then
		run_test $TEST
fi

rm -f ${UBD_TMP}
