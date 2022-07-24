#ifndef UBLKSRV_UTILS_INC
#define UBLKSRV_UTILS_INC

#ifdef __cplusplus
extern "C" {
#endif

/* Bit-mask values for 'flags' argument of create_daemon() */
#define BD_NO_CHDIR           01    /* Don't chdir("/") */
#define BD_NO_CLOSE_FILES     02    /* Don't close all open files */
#define BD_NO_REOPEN_STD_FDS  04    /* Don't reopen stdin, stdout, and
                                       stderr to /dev/null */
#define BD_NO_UMASK0         010    /* Don't do a umask(0) */
#define BD_MAX_CLOSE  8192          /* Maximum file descriptors to close if
                                       sysconf(_SC_OPEN_MAX) is indeterminate */
int start_daemon(int flags, void (*child_entry)(void *), void *data);

/* create pid file */
#define CPF_CLOEXEC 1
int create_pid_file(const char *pidFile, int flags, int *pid_fd);

#ifdef __cplusplus
}
#endif

#endif
