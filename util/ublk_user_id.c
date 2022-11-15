// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <stdio.h>
#include <stdlib.h>
#include "ublksrv.h"

static int print_dev_owner_id(int number)
{
	struct ublksrv_dev_data data = {
		.dev_id = number,
	};
	struct ublksrv_ctrl_dev *dev = ublksrv_ctrl_init(&data);
	int ret = ublksrv_ctrl_get_info(dev);

	if (ret >= 0) {
		const struct ublksrv_ctrl_dev_info *dinfo =
			ublksrv_ctrl_get_dev_info(dev);

		if (dinfo->flags & UBLK_F_UNPRIVILEGED_DEV)
			printf("%d:%d\n", dinfo->owner_uid, dinfo->owner_gid);
		else
			printf("%d:%d\n", -1, -1);
	} else {
		printf("%d:%d\n", -1, -1);
	}

	ublksrv_ctrl_deinit(dev);

	return ret;
}

int main(int argc, char *argv[])
{
	long number;
	char *path;

	if (argc != 2)
		return -1;

	path = argv[1];

	/*
	 * ublkcN or ublkbN since it is called when
	 * udev add event is received
	 */
	number = strtol(&path[5], NULL, 10);

	if (number >= 0)
		print_dev_owner_id(number);

	return 0;
}
