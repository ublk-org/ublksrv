#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

ublk_docker_add()
{
	local name=$1
	local maj=$2
	local min=$3
	local uid=$4
	local container=$5

	if [[ "$name" == *"ublkc"* ]]; then
		docker exec -u 0 $container mknod /dev/$name c $maj $min
		docker exec -u 0 $container chown $uid /dev/$name
		docker exec -u 0 $container chmod 700 /dev/$name
	elif [[ "$name" == *"ublkb"* ]]; then
		docker exec -u 0 $container mknod /dev/$name b $maj $min
		docker exec -u 0 $container chown $uid /dev/$name
		docker exec -u 0 $container chmod 700 /dev/$name
	fi
}

ublk_docker_remove()
{
	local name=$1
	local maj=$2
	local min=$3
	local uid=$4
	local container=$5

	if [[ "$name" == *"ublkc"* ]]; then
		docker exec -u 0 $container rm /dev/$name
	elif [[ "$name" == *"ublkb"* ]]; then
		docker exec -u 0 $container rm /dev/$name
	fi
}

MY_DIR=$(cd "$(dirname "$0")";pwd)
DEV=$1
ID=`${MY_DIR}/ublk_user_id $1`

#echo $@ >> /tmp/udev_docker_udev.log

CONTAINERS=""

for C in $CONTAINERS; do
	if [ "$2" == "add" ]; then
		ublk_docker_add $DEV $3 $4 $ID $C
	elif [ "$2" == "remove" ]; then
		ublk_docker_remove $DEV $3 $4 $ID $C
	fi
done

if [ "$2" == "add" ]; then
	if [ "${ID}" != "-1:-1" ]; then
		/usr/bin/chown $ID /dev/$1 > /dev/null 2>&1
	fi
fi
