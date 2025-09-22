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
		ublk_err( "Fail to open file %s", pid_file);
		return fd;
	}

	ret = ftruncate(fd, 0);
	if (ret == -1) {
		ublk_err( "Could not truncate pid file %s, err %s",
				pid_file, strerror(errno));
		goto fail;
	}

	snprintf(buf, PID_PATH_LEN, "%ld\n", (long) getpid());
	if (write(fd, buf, strlen(buf)) != strlen(buf)) {
		ublk_err( "Fail to write %s to file %s",
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

void ublk_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);
}

void ublk_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_INFO, fmt, ap);
	va_end(ap);
}

#ifdef DEBUG
static unsigned int ublk_debug_mask;
void ublk_dbg(int level, const char *fmt, ...)
{
	if (level & ublk_debug_mask) {
		va_list ap;

		va_start(ap, fmt);
		vsyslog(LOG_ERR, fmt, ap);
		va_end(ap);
	}
}

void ublk_ctrl_dbg(int level, const char *fmt, ...)
{
	if (level & ublk_debug_mask) {
		va_list ap;

		va_start(ap, fmt);
		vfprintf(stdout, fmt, ap);
		va_end(ap);
	}
}

void ublk_set_debug_mask(unsigned mask)
{
	ublk_debug_mask = mask;
}

unsigned ublk_get_debug_mask(unsigned mask)
{
	return ublk_debug_mask;
}
#else
void ublk_set_debug_mask(unsigned mask)
{
}

unsigned ublk_get_debug_mask(unsigned mask)
{
	return 0;
}
#endif

cpu_set_t *ublk_make_cpuset(int num_sets, const char *cpuset)
{
	int i;
	char *ptr, *next, *tmp, *str = NULL;
	cpu_set_t *sets = NULL, *ret = NULL;

	if (!cpuset)
		return NULL;
	if (!(str = strdup(cpuset)))
		return NULL;

	for(i = 0, ptr = str; (ptr = strchr(ptr, '[')); i++) {
		if (!(ptr = strchr(ptr, ']')))
			break;
	}
	if (i != num_sets)
		goto finished;

	if (!(sets = calloc(sizeof(cpu_set_t), i)))
		goto finished;

	for (i = 0; i < num_sets; i++) {
		CPU_ZERO(&sets[i]);
	}
	for (i = 0, ptr = str;
	     i < num_sets;
	     i++, ptr = next) {
		if (!(ptr = strchr(ptr, '[')))
			goto finished;
		ptr++;
		if (!(next = strchr(ptr, ']')))
			goto finished;
		*next++ = '\0';
		/*
		 * ptr -> end now contains the cpuset string for
		 * the queue with index i
		 */

		do {
			tmp = strchr(ptr, ',');
			if (tmp)
				*tmp++ = '\0';
			CPU_SET(strtol(ptr, NULL, 10), &sets[i]);
			ptr = tmp;
		} while (ptr && *ptr);
	}

	ret = sets;
	sets = NULL;
	
 finished:
	free(sets);
	free(str);
	return ret;
}
