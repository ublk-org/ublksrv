# SPDX-License-Identifier: MIT or GPL-2.0-only
#!/bin/bash

DIR=$(cd "$(dirname "$0")";pwd)

#. $DIR/common/fio_common

export UBLK=${DIR}/../ublk
export TEST_DIR=$DIR
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

run_test_grp() {
	local D=$1
	for ITEM in `ls ${D} | grep "^[0-9]" | grep -v "~$"`; do
			#echo $D/$ITEM
			run_test $D/$ITEM
	done
}

run_test_all() {
	local D=$1
	local GRPS="generic null loop qcow2"
	for G in $GRPS; do
			run_test_grp $D/$G
	done
}

TEST=$1

[ ! -c /dev/ublk-control ] && echo 'please run "modprobe ublk_drv" first' && exit -1

TDIR=$3
if [ "${TDIR:0:1}" != "/" ]; then
	TDIR=`dirname $PWD`/${TDIR}
fi

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
	fi
done

rm -f ${UBLK_TMP}
