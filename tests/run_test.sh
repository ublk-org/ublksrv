#!/bin/bash
# SPDX-License-Identifier: MIT or GPL-2.0-only

DIR=$(cd "$(dirname "$0")";pwd)
cd $DIR

#. $DIR/common/fio_common

: ${UBLK:=${DIR}/../ublk}
if ! command -v "${UBLK}" &> /dev/null; then
	echo "error: ublk command could not be found: ${UBLK}"
	exit -1
fi

export UBLK
export TEST_DIR=$DIR
export UBLK_TMP=`mktemp /tmp/ublk_tmp_XXXXX`

[ ! -d ${UBLK_TMP_DIR} ] && mkdir ${UBLK_TMP_DIR}

run_test() {
	TS=$1

	NAME=`basename $TS`
	TMP=`dirname $TS`
	GRP=`basename $TMP`

	echo "running $GRP/$NAME" | tee /dev/kmsg
	sh -c $TS &
	local TPID=$!
	local timeout=250
	local count=0
	while [ $count -lt $timeout ]; do
		sleep 1
		kill -0 $TPID > /dev/null 2>&1
		[ $? -ne 0 ] && break
		let count++
	done
	[ $count -ge $timeout ] && echo "timedout"
}

run_test_grp() {
	local D=$1
	for ITEM in `ls ${D} | grep "^[0-9]" | grep -v "~$"`; do
			#echo $D/$ITEM
			run_test $D/$ITEM
	done
}

run_test_all() {
	local D=$1
	local GRPS="generic $ALL_TGTS"
	for G in $GRPS; do
			run_test_grp $D/$G
	done
}

display_usage() {
	echo 'usage:'
	echo '    run_test.sh <test> <test_running_time> <temp_dir>'
}

TEST=$1
if [ -z "$TEST" ]; then
	echo 'error: no test specified'
	display_usage
	exit -1
fi

[ ! -c /dev/ublk-control ] && echo 'please run "modprobe ublk_drv" first' && exit -1

TDIR=$3
if [ -z "$TDIR" ]; then
	echo 'error: no temp dir specified'
	display_usage
	exit -1
fi

if [ "${TDIR:0:1}" != "/" ]; then
	TDIR=`dirname $PWD`/${TDIR}
fi

export ALL_TGTS="null loop qcow2 nbd"
export TRUNTIME=$2
export UBLK_TMP_DIR=$TDIR
export T_TYPE_PARAMS=""

[ ! -d ${UBLK_TMP_DIR} ] && mkdir -p ${UBLK_TMP_DIR}

_ITEMS=($(echo ${TEST} | tr ':' '\n'))
for _ITEM in "${_ITEMS[@]}"; do
	if [ -d ${_ITEM} ]; then
		run_test_grp ${_ITEM}
	elif [ -f ${_ITEM} ]; then
		run_test ${_ITEM}
	elif [ `basename ${_ITEM}` = "all" ]; then
		run_test_all `dirname ${_ITEM}`
	else
		echo "error: test suite not found: ${_ITEM}"
		exit -1
	fi
done

rm -f ${UBLK_TMP}
