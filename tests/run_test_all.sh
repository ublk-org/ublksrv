#!/bin/bash

DIR=$(cd "$(dirname "$0")";pwd)

export TRUNTIME=$1

GRPS="generic null loop"
for G in $GRPS; do
		$DIR/run_test.sh $DIR/$G
done
