/*
 * Part of the code is from the book of "The Linux Programming Interface".
 */
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <string.h>

#include "utils.h"

/* Lock a file region (private; public interfaces below) */
static int lockReg(int fd, int cmd, int type, int whence, int start, off_t len)
{
    struct flock fl;

    fl.l_type = type;
    fl.l_whence = whence;
    fl.l_start = start;
    fl.l_len = len;

    return fcntl(fd, cmd, &fl);
}

int                     /* Lock a file region using nonblocking F_SETLK */
lockRegion(int fd, int type, int whence, int start, int len)
{
    return lockReg(fd, F_SETLK, type, whence, start, len);
}

int                     /* Lock a file region using blocking F_SETLKW */
lockRegionWait(int fd, int type, int whence, int start, int len)
{
    return lockReg(fd, F_SETLKW, type, whence, start, len);
}

/* Test if a file region is lockable. Return 0 if lockable, or
   PID of process holding incompatible lock, or -1 on error. */
pid_t
regionIsLocked(int fd, int type, int whence, int start, int len)
{
    struct flock fl;

    fl.l_type = type;
    fl.l_whence = whence;
    fl.l_start = start;
    fl.l_len = len;

    if (fcntl(fd, F_GETLK, &fl) == -1)
        return -1;

    return (fl.l_type == F_UNLCK) ? 0 : fl.l_pid;
}

/* Open/create the file named in 'pidFile', lock it, optionally set the
   close-on-exec flag for the file descriptor, write our PID into the file,
   and (in case the caller is interested) return the file descriptor
   referring to the locked file. The caller is responsible for deleting
   'pidFile' file (just) before process termination. 'progName' should be the
   name of the calling program (i.e., argv[0] or similar), and is used only for
   diagnostic messages. If we can't open 'pidFile', or we encounter some other
   error, then we print an appropriate diagnostic and terminate. */
int create_pid_file(const char *pidFile, int flags, int *pid_fd)
{
#define BUF_SIZE 100            /* Large enough to hold maximum PID as string */
    int fd;
    char buf[BUF_SIZE];
    int ret = -2;

    fd = open(pidFile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        syslog(LOG_ERR, "Could not open PID file %s", pidFile);
        goto out;
    }

    *pid_fd = fd;

    if (flags & CPF_CLOEXEC) {

        /* Set the close-on-exec file descriptor flag */

        /* Instead of the following steps, we could (on Linux) have opened the
           file with O_CLOEXEC flag. However, not all systems support open()
           O_CLOEXEC (which was standardized only in SUSv4), so instead we use
           fcntl() to set the close-on-exec flag after opening the file */

        flags = fcntl(fd, F_GETFD);                     /* Fetch flags */
        if (flags == -1) {
            syslog(LOG_ERR, "Could not get flags for PID file %s", pidFile);
            goto out;
	}

        flags |= FD_CLOEXEC;                            /* Turn on FD_CLOEXEC */

        if (fcntl(fd, F_SETFD, flags) == -1) {           /* Update flags */
            syslog(LOG_ERR, "Could not set flags for PID file %s", pidFile);
            goto out;
	}
    }

    if (lockRegion(fd, F_WRLCK, SEEK_SET, 0, 0) == -1) {
        if (errno  == EAGAIN || errno == EACCES)
            syslog(LOG_ERR, "PID file '%s' is locked; probably "
                     "the daemon is already running", pidFile);
        else
            syslog(LOG_ERR, "Unable to lock PID file '%s'", pidFile);
        goto out;
    }

    ret = -1;
    if (ftruncate(fd, 0) == -1) {
        syslog(LOG_ERR, "Could not truncate PID file '%s'", pidFile);
        goto out;
    }

    snprintf(buf, BUF_SIZE, "%ld\n", (long) getpid());
    if (write(fd, buf, strlen(buf)) != strlen(buf)) {
        syslog(LOG_ERR, "Writing to PID file '%s'", pidFile);
    } else {
        ret = 0;
    }
 out:
    return ret;
}

