#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

ublk_docker_add()
{
	local name=$1
	local maj=$2
	local min=$3
	local uid=$4
	local container=$5

	#echo "docker add $name" >> /tmp/udev_docker_udev.log
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

	#echo "docker remove $name" >> /tmp/udev_docker_udev.log
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

#add ublk devices for interested containers
if [ "$2" == "add" ]; then
	if CONTAINERS=`docker ps --format "{{.Names}}"`; then
		#echo $CONTAINERS >> /tmp/udev_docker_udev.log
		for C in $CONTAINERS; do
			if ps -ax | grep docker | grep $ID > /dev/null 2>&1; then
				ublk_docker_add $DEV $3 $4 $ID $C
			fi
		done
	fi
elif [ "$2" == "remove" ]; then
	if CONTAINERS=`docker ps --format "{{.Names}}"`; then
		#echo $CONTAINERS >> /tmp/udev_docker_udev.log
		for C in $CONTAINERS; do
			ublk_docker_remove $DEV $3 $4 $ID $C
		done
	fi
fi

if [ "$2" == "add" ]; then
	if [ "${ID}" != "-1:-1" ]; then
		/usr/bin/chown $ID /dev/$1 > /dev/null 2>&1
	fi
fi
