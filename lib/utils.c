// SPDX-License-Identifier: MIT or LGPL-2.1-only

#include <config.h>

#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <string.h>
#include "ublksrv_priv.h"

/*
 * We don't need to lock file since the device id is unique
 */
int create_pid_file(const char *pid_file, int *pid_fd)
{
#define PID_PATH_LEN  256
	char buf[PID_PATH_LEN];
	int fd, ret;

	fd = open(pid_file, O_RDWR | O_CREAT | O_CLOEXEC,
			S_IRUSR | S_IWUSR);
	if (fd < 0) {
		syslog(LOG_ERR, "Fail to open file %s", pid_file);
		return fd;
	}

	ret = ftruncate(fd, 0);
	if (ret == -1) {
		syslog(LOG_ERR, "Could not truncate pid file %s, err %s",
				pid_file, strerror(errno));
		goto fail;
	}

	snprintf(buf, PID_PATH_LEN, "%ld\n", (long) getpid());
	if (write(fd, buf, strlen(buf)) != strlen(buf)) {
		syslog(LOG_ERR, "Fail to write %s to file %s",
				buf, pid_file);
		ret = -1;
	} else {
		*pid_fd = fd;
	}
 fail:
	if (ret) {
		close(fd);
		unlink(pid_file);
	}
	return ret;
}
